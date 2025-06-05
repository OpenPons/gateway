// Package store provides a persistence abstraction layer for the OpenPons Gateway.
// It defines interfaces for data storage and retrieval, with implementations
// for backends like SQLite, etcd, PostgreSQL, or Redis.
package store

import (
	"context"
	"errors" // Ensure this is the actual import used by errors.New
)

// EventType defines the type of change in a watch event.
type EventType int

const (
	// EventTypeCreate signifies a new key/value was created.
	EventTypeCreate EventType = iota
	// EventTypeUpdate signifies an existing key/value was updated.
	EventTypeUpdate
	// EventTypeDelete signifies a key/value was deleted.
	EventTypeDelete
)

// WatchEvent represents a change notification for a key or prefix.
type WatchEvent struct {
	Type      EventType
	Key       string
	Value     []byte // Value will be nil for EventTypeDelete
	PrevValue []byte // Optional: Previous value, if available and meaningful
}

// Store is the interface for a key-value persistence layer.
// Implementations could include SQLite, etcd, Redis, etc.
type Store interface {
	// Get retrieves the value for a given key.
	// Returns an error (e.g., ErrNotFound) if the key does not exist.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value for a given key, overwriting if it exists.
	Set(ctx context.Context, key string, value []byte) error

	// Delete removes a key and its value.
	// Should not error if the key doesn't exist.
	Delete(ctx context.Context, key string) error

	// List retrieves all key-value pairs matching a given prefix.
	List(ctx context.Context, prefix string) (map[string][]byte, error)

	// Watch returns a channel that streams WatchEvent updates for keys matching a prefix.
	// The watch continues until the provided context is cancelled or an error occurs.
	// The returned channel will be closed by the Store implementation when the watch stops.
	Watch(ctx context.Context, keyPrefix string) (<-chan WatchEvent, error)

	// Close cleans up the store connection.
	Close() error

	// BeginTransaction starts a new transaction.
	// The returned Transaction object should be used for all operations within that transaction.
	BeginTransaction(ctx context.Context) (Transaction, error)
}

// Transaction defines operations that can be performed within a store transaction.
type Transaction interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte) error
	Delete(ctx context.Context, key string) error
	// List may or may not be supported in a transaction depending on backend capabilities
	// List(ctx context.Context, prefix string) (map[string][]byte, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// ErrNotFound is returned by Get when a key is not found in the store.
var ErrNotFound = errors.New("store: key not found")
