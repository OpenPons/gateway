package store

import (
	"context"
	"database/sql"
	"errors" // For a proper ErrNotFound
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// Compile-time check to ensure SQLiteStore implements the Store interface.
var _ Store = (*SQLiteStore)(nil)

// SQLiteStore implements the Store interface using SQLite.
type SQLiteStore struct {
	db     *sql.DB
	dbPath string

	// For Watch functionality
	mu                      sync.RWMutex
	writeMu                 sync.Mutex                   // Mutex to serialize write operations
	watchers                map[string][]chan WatchEvent // keyPrefix -> list of watcher channels
	watcherChannelCloseOnce map[chan WatchEvent]*sync.Once
	stopPolling             chan struct{}
	pollingDone             chan struct{} // To signal poller has exited
	pollInterval            time.Duration
	lastPolledTime          time.Time // Added to track last poll time for changes
}

// NewSQLiteStore creates a new SQLiteStore.
// NewSQLiteStore creates a new SQLiteStore.
// dsn should be in the format "sqlite:///path/to/database.db" or "sqlite://:memory:"
func NewSQLiteStore(dsn string, pollInterval time.Duration) (*SQLiteStore, error) {
	log.Printf("Initializing SQLite store with DSN: %s", dsn)

	// Correctly parse the DSN to extract the path for sql.Open
	if !strings.HasPrefix(dsn, "sqlite://") {
		return nil, fmt.Errorf("invalid DSN: must start with sqlite://")
	}
	dbPath := strings.TrimPrefix(dsn, "sqlite://")

	// Append pragmas to the actual path, not the full DSN string
	actualDSN := dbPath
	// For file-based databases or shared in-memory databases, append WAL pragmas.
	// Plain ":memory:" (non-shared) typically doesn't need or benefit from WAL and might default to journal_mode=memory.
	// Always add pragmas for consistency, including for :memory: if it's file-based (e.g. file::memory:?cache=shared)
	pragmas := "_journal_mode=WAL&_busy_timeout=5000&_txlock=exclusive" // Added _txlock=exclusive
	if strings.Contains(actualDSN, "?") {
		actualDSN = actualDSN + "&" + pragmas
	} else {
		actualDSN = actualDSN + "?" + pragmas
	}
	// If dbPath was :memory: and no params, actualDSN becomes :memory:?_journal_mode=WAL...
	// If dbPath was file::memory:?cache=shared, actualDSN becomes file::memory:?cache=shared&_journal_mode=WAL...

	log.Printf("Attempting to open SQLite with actual DSN: %s", actualDSN)
	db, err := sql.Open("sqlite3", actualDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database with DSN '%s' (original path '%s'): %w", actualDSN, dbPath, err)
	}
	// db.SetMaxOpenConns(1) // Serialize all DB operations through a single connection -- REMOVED TO ADDRESS HANGS

	// Create table if it doesn't exist
	// Using a simple key-value table. Key is TEXT PRIMARY KEY for unique constraint and indexing.
	// Value is BLOB to store any byte array.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS kv_store (
			key TEXT PRIMARY KEY,
			value BLOB,
			last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create kv_store table: %w", err)
	}
	// Index on last_modified for efficient polling of changes if needed
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_kv_store_last_modified ON kv_store(last_modified)`)
	if err != nil {
		// Non-fatal, but log it
		log.Printf("Warning: Failed to create index on last_modified: %v", err)
	}

	s := &SQLiteStore{
		db:                      db,
		dbPath:                  dbPath,
		watchers:                make(map[string][]chan WatchEvent),
		watcherChannelCloseOnce: make(map[chan WatchEvent]*sync.Once),
		stopPolling:             make(chan struct{}),
		pollingDone:             make(chan struct{}), // Initialize pollingDone
		pollInterval:            pollInterval,
	}

	// For a real Watch implementation, you might start a poller goroutine here
	// or use SQLite's update hook if possible (though that's more complex with cgo).
	go s.startChangePolling() // Start the centralized poller

	return s, nil
}

// Get retrieves the value for a given key.
func (s *SQLiteStore) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM kv_store WHERE key = ?", key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound // Use package-level ErrNotFound
		}
		return nil, fmt.Errorf("sqlite Get failed for key '%s': %w", key, err)
	}
	return value, nil
}

// Set stores a value for a given key.
func (s *SQLiteStore) Set(ctx context.Context, key string, value []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// Using INSERT OR REPLACE (UPSERT)
	stmt, err := s.db.PrepareContext(ctx, "INSERT OR REPLACE INTO kv_store (key, value, last_modified) VALUES (?, ?, CURRENT_TIMESTAMP)")
	if err != nil {
		return fmt.Errorf("sqlite Set prepare failed for key '%s': %w", key, err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, key, value)
	if err != nil {
		return fmt.Errorf("sqlite Set exec failed for key '%s': %w", key, err)
	}
	// Notify watchers (simplified)
	s.notifyWatchers(key, value, EventTypeUpdate) // Or determine if it was Create vs Update
	return nil
}

// Delete removes a key and its value.
func (s *SQLiteStore) Delete(ctx context.Context, key string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	stmt, err := s.db.PrepareContext(ctx, "DELETE FROM kv_store WHERE key = ?")
	if err != nil {
		return fmt.Errorf("sqlite Delete prepare failed for key '%s': %w", key, err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, key)
	if err != nil {
		return fmt.Errorf("sqlite Delete exec failed for key '%s': %w", key, err)
	}
	// Notify watchers
	s.notifyWatchers(key, nil, EventTypeDelete)
	return nil
}

// List retrieves all key-value pairs matching a given prefix.
func (s *SQLiteStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM kv_store WHERE key LIKE ?", prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("sqlite List query failed for prefix '%s': %w", prefix, err)
	}
	defer rows.Close()

	results := make(map[string][]byte)
	for rows.Next() {
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("sqlite List scan failed: %w", err)
		}
		results[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite List rows error: %w", err)
	}
	return results, nil
}

// Watch returns a channel that streams WatchEvent updates.
// This is a simplified polling-based implementation for MVP.
// A more robust solution would use database triggers or a proper WAL reader if possible.
func (s *SQLiteStore) Watch(ctx context.Context, keyPrefix string) (<-chan WatchEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	eventChan := make(chan WatchEvent, 10) // Buffered channel

	// Store the channel associated with the prefix
	s.watchers[keyPrefix] = append(s.watchers[keyPrefix], eventChan)
	s.watcherChannelCloseOnce[eventChan] = &sync.Once{} // Associate a sync.Once

	// Simple poller for this specific watch request (not ideal for many watchers)
	// A central poller (startChangePolling) would be better.
	// For MVP, this demonstrates the concept.
	go func() {
		defer func() {
			s.mu.Lock()
			// Remove this specific channel from the list for this prefix
			var updatedWatchers []chan WatchEvent
			for _, ch := range s.watchers[keyPrefix] {
				if ch != eventChan {
					updatedWatchers = append(updatedWatchers, ch)
				}
			}
			if len(updatedWatchers) == 0 {
				delete(s.watchers, keyPrefix)
			} else {
				s.watchers[keyPrefix] = updatedWatchers
			}

			// Safely close the eventChan using sync.Once
			if once, ok := s.watcherChannelCloseOnce[eventChan]; ok {
				once.Do(func() {
					close(eventChan)
				})
				delete(s.watcherChannelCloseOnce, eventChan) // Clean up the sync.Once entry
			} else {
				// This case should ideally not happen if logic is correct,
				// but if it does, it means sync.Once was not found for this channel.
				// Potentially log an error or handle as an unexpected state.
				// For now, we assume 'ok' is true.
				// If not, 'close(eventChan)' might panic if already closed by store.Close().
				// The sync.Once mechanism is designed to prevent this.
			}
			s.mu.Unlock()
			log.Printf("Stopped watching prefix: %s", keyPrefix)
		}()

		log.Printf("Started watching prefix: %s", keyPrefix)
		// Send initial state (optional, depends on desired Watch semantics)
		// currentItems, err := s.List(ctx, keyPrefix)
		// if err == nil {
		// 	for k, v := range currentItems {
		// 		eventChan <- WatchEvent{Type: EventTypeUpdate, Key: k, Value: v} // Or Create
		// 	}
		// }

		// This goroutine will be stopped when the context is cancelled.
		// The actual event generation is handled by notifyWatchers (for direct Set/Delete)
		// and by the centralized startChangePolling goroutine.
		// This goroutine just keeps the channel alive for this specific watcher until its context is done.
		<-ctx.Done()
	}()

	return eventChan, nil
}

// notifyWatchers sends events to relevant watcher channels.
// Called by Set/Delete for immediate notifications, and by the central poller.
// This is a simplified implementation. A real one would check last_modified times
// or use a more sophisticated change detection mechanism.
func (s *SQLiteStore) notifyWatchers(key string, value []byte, eventType EventType) {
	s.mu.RLock() // Lock for reading watchers map
	defer s.mu.RUnlock()

	event := WatchEvent{
		Type:  eventType,
		Key:   key,
		Value: value, // Value is nil for Delete
	}

	for prefix, channels := range s.watchers {
		if strings.HasPrefix(key, prefix) {
			for _, ch := range channels {
				select {
				case ch <- event:
				default:
					// Channel is full or closed, log or handle as needed
					log.Printf("Watch channel full for prefix %s, event for key %s dropped", prefix, key)
				}
			}
		}
	}
}

// Close cleans up the store connection.
func (s *SQLiteStore) Close() error {
	log.Println("Closing SQLite store...")
	s.mu.Lock() // Ensure exclusive access for closing operations on watcher structures
	// No defer s.mu.Unlock() here, as db closing happens after this block

	// Signal polling goroutine to stop and wait for it
	if s.stopPolling != nil {
		// Check if already closed to prevent panic
		select {
		case <-s.stopPolling:
			// Already closed
		default:
			close(s.stopPolling)
		}
		s.stopPolling = nil // Prevent double close if Close is called again

		// Wait for poller to finish, with a timeout
		select {
		case <-s.pollingDone:
			log.Println("SQLiteStore: Central change poller confirmed stopped.")
		case <-time.After(2 * time.Second): // Increased timeout to 2 seconds
			log.Println("SQLiteStore: Timeout waiting for central change poller to stop.")
		}
	}
	s.mu.Unlock() // Unlock after handling poller shutdown logic

	// Re-lock for closing watcher channels and db, or use a separate lock for db if needed.
	// For simplicity, using the same mu for now, but consider if db operations need finer-grained locking.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close all watcher channels
	for _, channels := range s.watchers { // Removed 'prefix' from here
		for _, ch := range channels {
			if once, ok := s.watcherChannelCloseOnce[ch]; ok {
				once.Do(func() {
					close(ch)
				})
				// No need to delete from watcherChannelCloseOnce here,
				// as the whole map will be cleared shortly.
			}
		}
	}
	s.watchers = make(map[string][]chan WatchEvent)                  // Clear watchers
	s.watcherChannelCloseOnce = make(map[chan WatchEvent]*sync.Once) // Clear sync.Once map

	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// startChangePolling is a centralized mechanism to poll for database changes.
func (s *SQLiteStore) startChangePolling() {
	defer close(s.pollingDone) // Signal exit when this goroutine finishes

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Goroutine to cancel the context when stopPolling is closed
	go func() {
		select {
		case <-s.stopPolling:
			cancel()
		case <-ctx.Done(): // If the poller's main context is done (e.g. on return), stop this goroutine
		}
	}()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	// Initialize lastPolledTime to current time to only get changes from now on.
	// Or, could query max(last_modified) on start if we want to catch up from last known state.
	s.mu.Lock() // Lock for initial lastPolledTime set
	s.lastPolledTime = time.Now().UTC()
	s.mu.Unlock()

	// Check if kv_store table exists before starting the poller loop
	var tableName string
	err := s.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='kv_store'").Scan(&tableName)
	if err != nil {
		log.Printf("SQLiteStore: Central change poller NOT starting. Failed to verify 'kv_store' table: %v", err)
		return // Do not start poller if table verification fails
	}
	if tableName != "kv_store" {
		log.Printf("SQLiteStore: Central change poller NOT starting. 'kv_store' table not found.")
		return
	}

	log.Println("SQLiteStore: Central change poller started.")

	for {
		select {
		case <-ticker.C:
			s.mu.RLock() // RLock for reading lastPolledTime
			queryTime := s.lastPolledTime
			s.mu.RUnlock()

			// Query for rows modified since the last poll time.
			// Using a slight buffer (e.g., 1 second before lastPolledTime) can help catch
			// transactions that might have committed around the exact microsecond of the last poll.
			// However, for simplicity, using `>` is fine for polling.
			rows, err := s.db.QueryContext(ctx, "SELECT key, value, last_modified FROM kv_store WHERE last_modified > ?", queryTime)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, sql.ErrConnDone) || strings.Contains(err.Error(), "database is closed") {
					log.Printf("SQLiteStore: Poller query cancelled or DB closed: %v", err)
					return // Exit poller if context is cancelled or DB is closed
				}
				log.Printf("SQLiteStore: Error polling for changes: %v", err)
				continue
			}

			var changedKeys []string
			maxModifiedTime := queryTime

			for rows.Next() {
				var key string
				var value []byte
				var lastModified time.Time // Read the last_modified timestamp
				if err := rows.Scan(&key, &value, &lastModified); err != nil {
					log.Printf("SQLiteStore: Error scanning changed row: %v", err)
					continue
				}
				// Notify watchers for this change.
				// EventTypeUpdate is used as we are polling for existing rows that changed.
				// New rows inserted after lastPolledTime will also be caught.
				// Deleted rows are not caught by this polling method directly, only by direct Delete calls.
				s.notifyWatchers(key, value, EventTypeUpdate)
				changedKeys = append(changedKeys, key)
				if lastModified.After(maxModifiedTime) {
					maxModifiedTime = lastModified
				}
			}
			rows.Close() // Important to close rows

			if len(changedKeys) > 0 {
				log.Printf("SQLiteStore: Poller detected changes for keys: %v", changedKeys)
			}

			// Update lastPolledTime to the time of the most recent modification found in this poll,
			// or to current time if no changes were found, to advance the polling window.
			s.mu.Lock()
			if maxModifiedTime.After(s.lastPolledTime) {
				s.lastPolledTime = maxModifiedTime
			} else {
				// If no changes with a newer timestamp, just advance to current time to avoid re-polling old data.
				// Add a small buffer to ensure we don't miss anything due to clock skew or transaction timing.
				s.lastPolledTime = time.Now().UTC().Add(-1 * time.Second)
			}
			s.mu.Unlock()

		case <-s.stopPolling:
			log.Println("SQLiteStore: Central change poller stopped.")
			return
		}
	}
}

// --- Transaction Implementation ---

// sqliteTx implements the Transaction interface for SQLite.
type sqliteTx struct {
	tx            *sql.Tx
	store         *SQLiteStore // Reference to the parent store for dispatching events
	pendingEvents []WatchEvent
}

// BeginTransaction starts a new SQLite transaction.
func (s *SQLiteStore) BeginTransaction(ctx context.Context) (Transaction, error) {
	txSQL, err := s.db.BeginTx(ctx, nil) // Renamed tx to txSQL to avoid conflict
	if err != nil {
		return nil, fmt.Errorf("sqlite: begin transaction: %w", err)
	}
	return &sqliteTx{tx: txSQL, store: s, pendingEvents: make([]WatchEvent, 0)}, nil
}

// Get retrieves a value within a transaction.
func (t *sqliteTx) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	query := "SELECT value FROM kv_store WHERE key = ?"
	err := t.tx.QueryRowContext(ctx, query, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound // Use package-level ErrNotFound
		}
		return nil, fmt.Errorf("sqlite tx get for key '%s': %w", key, err)
	}
	return value, nil
}

// Set stores a value within a transaction.
func (t *sqliteTx) Set(ctx context.Context, key string, value []byte) error {
	query := "INSERT OR REPLACE INTO kv_store (key, value, last_modified) VALUES (?, ?, CURRENT_TIMESTAMP)"
	stmt, err := t.tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("sqlite tx set prepare for key '%s': %w", key, err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, key, value)
	if err != nil {
		return fmt.Errorf("sqlite tx set exec for key '%s': %w", key, err)
	}
	// Get previous value for watch event
	prevValue, errGet := t.Get(ctx, key) // Use t.Get to read within the same transaction state if possible, or s.Get for committed state
	var eventType EventType
	if errGet != nil && !errors.Is(errGet, ErrNotFound) { // Use package-level ErrNotFound
		// Log error but proceed with Set, as Get was for watch event only
		log.Printf("SQLiteStore: tx.Set could not get previous value for key '%s': %v", key, errGet)
		eventType = EventTypeUpdate // Assume update if get fails for reasons other than not found
	} else if errors.Is(errGet, ErrNotFound) { // Use package-level ErrNotFound
		eventType = EventTypeCreate
		prevValue = nil // Ensure prevValue is nil for create events
	} else {
		eventType = EventTypeUpdate
	}

	t.pendingEvents = append(t.pendingEvents, WatchEvent{
		Type:      eventType,
		Key:       key,
		Value:     value,
		PrevValue: prevValue,
	})
	return nil
}

// Delete removes a key and its value within a transaction.
func (t *sqliteTx) Delete(ctx context.Context, key string) error {
	// Get value before deleting for watch event
	valueToDelete, errGet := t.Get(ctx, key)
	if errGet != nil && !errors.Is(errGet, ErrNotFound) { // Use package-level ErrNotFound
		log.Printf("SQLiteStore: tx.Delete could not get value for key '%s': %v. Event will have nil value.", key, errGet)
		valueToDelete = nil // Ensure value is nil if get fails
	} else if errors.Is(errGet, ErrNotFound) { // Use package-level ErrNotFound
		// Key doesn't exist, so no delete event to record, and no actual delete needed.
		// Or, if we want to record an "attempted delete on non-existent key", that's different.
		// For now, if not found, it's a no-op for events and the DB.
		return nil
	}

	stmt, err := t.tx.PrepareContext(ctx, "DELETE FROM kv_store WHERE key = ?")
	if err != nil {
		return fmt.Errorf("sqlite tx delete prepare for key '%s': %w", key, err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, key)
	if err != nil {
		return fmt.Errorf("sqlite tx delete exec for key '%s': %w", key, err)
	}

	t.pendingEvents = append(t.pendingEvents, WatchEvent{
		Type:      EventTypeDelete,
		Key:       key,
		Value:     nil, // Value is nil for delete
		PrevValue: valueToDelete,
	})
	return nil
}

// Commit commits the transaction.
func (t *sqliteTx) Commit(ctx context.Context) error {
	err := t.tx.Commit()
	if err != nil {
		return fmt.Errorf("sqlite tx commit: %w", err)
	}

	// After successful SQL commit, dispatch collected watch events
	if t.store != nil { // Ensure store is set
		for _, event := range t.pendingEvents {
			// Using a new context for dispatch as the transaction context might be done.
			// Or, pass the original request context if appropriate.
			// For simplicity, notifyWatchers doesn't use its context argument currently.
			t.store.notifyWatchers(event.Key, event.Value, event.Type) // Pass event.Type
		}
	}
	t.pendingEvents = nil // Clear after dispatch
	return nil
}

// Rollback aborts the transaction.
func (t *sqliteTx) Rollback(ctx context.Context) error {
	err := t.tx.Rollback()
	if err != nil {
		// sql.ErrTxDone is normal if Commit or Rollback was already called.
		if errors.Is(err, sql.ErrTxDone) {
			return nil // Or a specific error indicating it was already finalized
		}
		return fmt.Errorf("sqlite tx rollback: %w", err)
	}
	return nil
}

// func (s *SQLiteStore) startChangePolling() {
//  ticker := time.NewTicker(s.pollInterval)
//  defer ticker.Stop()
//  knownStates := make(map[string][]byte) // Or map[string]time.Time for last_modified
//
//  for {
//      select {
//      case <-ticker.C:
//          // Poll database for changes since last check
//          // Compare with knownStates
//          // Generate WatchEvents and call s.notifyWatchers
//      case <-s.stopPolling:
//          log.Println("SQLite change poller stopped.")
//          return
//      }
//  }
// }
