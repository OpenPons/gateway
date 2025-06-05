package routing

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockAdapter implements provider.ProviderAdapter for testing
type MockAdapter struct {
	id      string
	name    string
	pType   config.ProviderType
	pCfg    config.ProviderConfig
	healthy bool
}

func (m *MockAdapter) GetID() string                     { return m.id }
func (m *MockAdapter) GetName() string                   { return m.name }
func (m *MockAdapter) GetType() config.ProviderType      { return m.pType }
func (m *MockAdapter) GetConfig() *config.ProviderConfig { return &m.pCfg }
func (m *MockAdapter) ProviderInfo() provider.Info {
	return provider.Info{Name: m.name, Type: m.pType}
}
func (m *MockAdapter) ChatCompletion(ctx context.Context, request *provider.ChatCompletionRequest) (*provider.ChatCompletionResponse, error) {
	return nil, fmt.Errorf("mock adapter")
}
func (m *MockAdapter) StreamChatCompletion(ctx context.Context, request *provider.ChatCompletionRequest, stream io.Writer) error {
	return fmt.Errorf("mock adapter")
}
func (m *MockAdapter) GenerateEmbedding(ctx context.Context, request *provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
	return nil, fmt.Errorf("mock adapter")
}
func (m *MockAdapter) InvokeTool(ctx context.Context, request *provider.ToolInvocationRequest) (*provider.ToolInvocationResponse, error) {
	return nil, fmt.Errorf("mock adapter")
}
func (m *MockAdapter) StreamInvokeTool(ctx context.Context, requestStream <-chan *provider.ToolInvocationStreamChunk, responseStream chan<- *provider.ToolInvocationStreamChunk) error {
	return fmt.Errorf("mock adapter")
}
func (m *MockAdapter) AudioTranscription(ctx context.Context, request *provider.AudioTranscriptionRequest) (*provider.AudioTranscriptionResponse, error) {
	return nil, fmt.Errorf("mock adapter")
}
func (m *MockAdapter) TextToSpeech(ctx context.Context, request *provider.TextToSpeechRequest, stream io.Writer) error {
	return fmt.Errorf("mock adapter")
}
func (m *MockAdapter) HealthCheck(ctx context.Context) error {
	if m.healthy {
		return nil
	}
	return fmt.Errorf("mock adapter unhealthy")
}
func (m *MockAdapter) Init(cfg *config.ProviderConfig, sr provider.SecretRetriever) error { return nil }
func (m *MockAdapter) Shutdown() error                                                    { return nil }

// MockRegistry implements provider.RegistryInterface for testing
type MockRegistry struct {
	adapters map[string]*MockAdapter
}

func NewMockRegistry() *MockRegistry {
	return &MockRegistry{
		adapters: make(map[string]*MockAdapter),
	}
}

func (r *MockRegistry) AddAdapter(id string, adapter *MockAdapter) {
	r.adapters[id] = adapter
}

func (r *MockRegistry) GetAdapter(providerID string) (provider.ProviderAdapter, error) {
	adapter, exists := r.adapters[providerID]
	if !exists {
		return nil, fmt.Errorf("no adapter found for provider ID: %s", providerID)
	}
	return adapter, nil
}

// MockSecretStore is a minimal mock for store.Store and store.Transaction.
type MockSecretStore struct {
	mu       sync.RWMutex
	data     map[string][]byte
	watchers []watcher
	GetFn    func(ctx context.Context, key string) ([]byte, error)
	SetFn    func(ctx context.Context, key string, value []byte) error
	// DeleteFn func(ctx context.Context, key string) error // Optional: if custom delete logic is needed
}

type watcher struct {
	ch     chan store.WatchEvent
	prefix string
}

// NewMockSecretStore creates a new MockSecretStore.
func NewMockSecretStore() *MockSecretStore {
	return &MockSecretStore{
		data:     make(map[string][]byte),
		watchers: make([]watcher, 0),
	}
}

// store.Store interface methods
func (s *MockSecretStore) Get(ctx context.Context, key string) ([]byte, error) {
	if s.GetFn != nil {
		return s.GetFn(ctx, key)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.data[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return val, nil
}
func (s *MockSecretStore) Set(ctx context.Context, key string, value []byte) error {
	if s.SetFn != nil {
		return s.SetFn(ctx, key, value)
	}
	s.mu.Lock()
	s.data[key] = value
	s.mu.Unlock() // Unlock before notifying to avoid deadlocks if watcher calls back into store

	// Notify watchers
	s.mu.RLock() // RLock for reading watchers slice
	for _, w := range s.watchers {
		if strings.HasPrefix(key, w.prefix) {
			valueCopy := make([]byte, len(value))
			copy(valueCopy, value)
			select {
			case w.ch <- store.WatchEvent{Type: store.EventTypeUpdate, Key: key, Value: valueCopy}: // Changed EventTypePut to EventTypeUpdate
			default: // Don't block if watcher channel is full or not read
			}
		}
	}
	s.mu.RUnlock()
	return nil
}
func (s *MockSecretStore) Delete(ctx context.Context, key string) error {
	// if s.DeleteFn != nil {
	// 	return s.DeleteFn(ctx, key)
	// }
	s.mu.Lock()
	_, ok := s.data[key]
	if !ok {
		s.mu.Unlock()
		return store.ErrNotFound // Or return nil for idempotency
	}
	delete(s.data, key)
	s.mu.Unlock() // Unlock before notifying

	// Notify watchers
	s.mu.RLock()
	for _, w := range s.watchers {
		if strings.HasPrefix(key, w.prefix) {
			select {
			case w.ch <- store.WatchEvent{Type: store.EventTypeDelete, Key: key}:
			default: // Don't block
			}
		}
	}
	s.mu.RUnlock()
	return nil
}
func (s *MockSecretStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make(map[string][]byte)
	for key, value := range s.data {
		if strings.HasPrefix(key, prefix) {
			// Create a copy of the value to avoid external modification of the mock's internal state
			valueCopy := make([]byte, len(value))
			copy(valueCopy, value)
			results[key] = valueCopy
		}
	}
	return results, nil
}
func (s *MockSecretStore) Watch(ctx context.Context, keyPrefix string) (<-chan store.WatchEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create a buffered channel to prevent blocking if events are sent before listener is ready
	// or if listener is slow. Buffer size can be adjusted.
	ch := make(chan store.WatchEvent, 10)
	s.watchers = append(s.watchers, watcher{ch: ch, prefix: keyPrefix})
	return ch, nil
}
func (s *MockSecretStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.watchers {
		close(w.ch)
	}
	s.watchers = nil                 // Clear the list of watchers
	s.data = make(map[string][]byte) // Optionally clear data on close
	return nil
}
func (s *MockSecretStore) BeginTransaction(ctx context.Context) (store.Transaction, error) {
	return s, nil
}
func (s *MockSecretStore) Commit(ctx context.Context) error {
	// For this simple mock, operations are applied directly, so Commit is a no-op.
	return nil
}
func (s *MockSecretStore) Rollback(ctx context.Context) error {
	// For this simple mock, operations are applied directly.
	// A true rollback would require staging changes, which this mock doesn't do.
	return nil
}

func TestNewRouter(t *testing.T) {
	router := NewRouter(nil, nil)
	require.NotNil(t, router, "NewRouter should not return nil")
	assert.NotNil(t, router.rng, "RNG should be initialized")
	assert.NotNil(t, router.pendingRequests, "PendingRequests map should be initialized")
}

func TestPendingRequestCounters(t *testing.T) {
	router := NewRouter(nil, nil)

	targetRef1 := "model-1"
	targetRef2 := "model-2"

	// Test GetPendingRequests on non-existent target
	assert.Equal(t, int32(0), router.GetPendingRequests("non-existent"), "Pending requests for non-existent target should be 0")

	// Test IncrementPendingRequests
	router.IncrementPendingRequests(targetRef1)
	assert.Equal(t, int32(1), router.GetPendingRequests(targetRef1), "Pending requests for targetRef1 should be 1 after one increment")

	router.IncrementPendingRequests(targetRef1)
	assert.Equal(t, int32(2), router.GetPendingRequests(targetRef1), "Pending requests for targetRef1 should be 2 after two increments")

	router.IncrementPendingRequests(targetRef2)
	assert.Equal(t, int32(1), router.GetPendingRequests(targetRef2), "Pending requests for targetRef2 should be 1 after one increment")

	// Test DecrementPendingRequests
	router.DecrementPendingRequests(targetRef1)
	assert.Equal(t, int32(1), router.GetPendingRequests(targetRef1), "Pending requests for targetRef1 should be 1 after one decrement")

	router.DecrementPendingRequests(targetRef2)
	assert.Equal(t, int32(0), router.GetPendingRequests(targetRef2), "Pending requests for targetRef2 should be 0 after one decrement")

	// Test DecrementPendingRequests on target with 0 pending requests
	router.DecrementPendingRequests(targetRef2)
	assert.Equal(t, int32(-1), router.GetPendingRequests(targetRef2), "Pending requests for targetRef2 should be -1 after decrementing from 0 (atomic ops allow this)")

	// Reset counter for targetRef2 for clarity in next steps if any
	atomic.StoreInt32(router.pendingRequests[targetRef2], 0)

	router.DecrementPendingRequests("non-existent-decrement")
	// No assertion for value, just ensure it doesn't panic and logs (log is discarded in TestMain)
}

func TestRouteMatches(t *testing.T) {
	tests := []struct {
		name     string
		reqCtx   IncomingRequestContext
		match    config.RouteMatch
		expected bool
	}{
		{
			name:     "PathPrefix match success",
			reqCtx:   IncomingRequestContext{Path: "/v1/chat/completions"},
			match:    config.RouteMatch{PathPrefix: "/v1/chat"},
			expected: true,
		},
		{
			name:     "PathPrefix match fail",
			reqCtx:   IncomingRequestContext{Path: "/v2/models"},
			match:    config.RouteMatch{PathPrefix: "/v1/chat"},
			expected: false,
		},
		{
			name:     "ModelID match success (HTTPLLM)",
			reqCtx:   IncomingRequestContext{Path: "/v1/chat/completions", ModelID: "gpt-4", Protocol: config.ProtocolHTTPLLM},
			match:    config.RouteMatch{ModelID: "gpt-4"},
			expected: true,
		},
		{
			name:     "ModelID match fail (HTTPLLM)",
			reqCtx:   IncomingRequestContext{Path: "/v1/chat/completions", ModelID: "gpt-3.5", Protocol: config.ProtocolHTTPLLM},
			match:    config.RouteMatch{ModelID: "gpt-4"},
			expected: false,
		},
		{
			name:     "Header match success",
			reqCtx:   IncomingRequestContext{Headers: http.Header{"X-Custom-Header": []string{"value1"}}},
			match:    config.RouteMatch{Headers: map[string]string{"X-Custom-Header": "value1"}},
			expected: true,
		},
		{
			name:     "Empty match criteria (should always match)",
			reqCtx:   IncomingRequestContext{Path: "/anything"},
			match:    config.RouteMatch{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, routeMatches(tt.reqCtx, &tt.match))
		})
	}
}

func TestSelectTargetWeightedRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(1)) // Seeded for deterministic tests
	var rngLock sync.Mutex

	tests := []struct {
		name           string
		targets        []config.RouteTarget
		expectError    bool
		expectedCounts map[string]int // For checking distribution over many runs
		totalRuns      int            // Number of times to run selection for distribution check
	}{
		{
			name:        "No targets",
			targets:     []config.RouteTarget{},
			expectError: true,
		},
		{
			name: "Single target",
			targets: []config.RouteTarget{
				{Ref: "t1", Weight: 100},
			},
			expectError:    false,
			expectedCounts: map[string]int{"t1": 1000},
			totalRuns:      1000,
		},
		{
			name: "Two targets, one zero weight",
			targets: []config.RouteTarget{
				{Ref: "t1", Weight: 100},
				{Ref: "t2", Weight: 0},
			},
			expectError:    false,
			expectedCounts: map[string]int{"t1": 1000}, // Only t1 should be selected
			totalRuns:      1000,
		},
		{
			name: "Simple 50/50 distribution",
			targets: []config.RouteTarget{
				{Ref: "t1", Weight: 50},
				{Ref: "t2", Weight: 50},
			},
			expectError: false,
			totalRuns:   2000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.totalRuns > 0 { // Distribution test
				counts := make(map[string]int)
				for i := 0; i < tt.totalRuns; i++ {
					selected, err := selectTargetWeightedRandom(tt.targets, rng, &rngLock)
					if tt.expectError {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					require.NotNil(t, selected)
					counts[selected.Ref]++
				}

				if tt.expectedCounts != nil {
					assert.Equal(t, tt.expectedCounts, counts)
				} else if tt.name == "Simple 50/50 distribution" {
					mean := float64(tt.totalRuns) / 2.0
					assert.InDelta(t, mean, counts["t1"], mean*0.2, "Distribution for t1 is off (50/50)")
					assert.InDelta(t, mean, counts["t2"], mean*0.2, "Distribution for t2 is off (50/50)")
				}
			} else { // Single run test (mostly for error cases or single target)
				selected, err := selectTargetWeightedRandom(tt.targets, rng, &rngLock)
				if tt.expectError {
					assert.Error(t, err)
					assert.Nil(t, selected)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, selected)
					if len(tt.targets) == 1 {
						assert.Equal(t, tt.targets[0].Ref, selected.Ref)
					}
				}
			}
		})
	}
}

func TestSelectTargetFailover(t *testing.T) {
	registry := NewMockRegistry()

	// Add healthy adapter
	healthyAdapter := &MockAdapter{
		id:      "p-healthy",
		name:    "healthy-provider",
		pType:   config.ProviderTypeLLM,
		healthy: true,
	}
	registry.AddAdapter("p-healthy", healthyAdapter)

	// Add unhealthy adapter
	unhealthyAdapter := &MockAdapter{
		id:      "p-unhealthy",
		name:    "unhealthy-provider",
		pType:   config.ProviderTypeLLM,
		healthy: false,
	}
	registry.AddAdapter("p-unhealthy", unhealthyAdapter)

	runtimeCfg := &config.RuntimeConfig{
		Models: []config.ModelConfig{
			{ID: "m-healthy", ProviderID: "p-healthy"},
			{ID: "m-unhealthy", ProviderID: "p-unhealthy"},
		},
	}

	tests := []struct {
		name              string
		targets           []config.RouteTarget
		expectedTargetRef string
		expectError       bool
	}{
		{
			name:        "No targets",
			targets:     []config.RouteTarget{},
			expectError: true,
		},
		{
			name: "First target healthy",
			targets: []config.RouteTarget{
				{Ref: "m-healthy"},
				{Ref: "m-unhealthy"},
			},
			expectedTargetRef: "m-healthy",
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selected, err := selectTargetFailover(tt.targets, registry, runtimeCfg, config.ProtocolHTTPLLM)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, selected)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, selected)
				assert.Equal(t, tt.expectedTargetRef, selected.Ref)
			}
		})
	}
}

func TestSelectTargetLeastPending(t *testing.T) {
	registry := NewMockRegistry()

	// Add healthy adapters
	healthyAdapter1 := &MockAdapter{
		id:      "p-lp-1",
		name:    "lp-provider-1",
		pType:   config.ProviderTypeLLM,
		healthy: true,
	}
	registry.AddAdapter("p-lp-1", healthyAdapter1)

	healthyAdapter2 := &MockAdapter{
		id:      "p-lp-2",
		name:    "lp-provider-2",
		pType:   config.ProviderTypeLLM,
		healthy: true,
	}
	registry.AddAdapter("p-lp-2", healthyAdapter2)

	runtimeCfg := &config.RuntimeConfig{
		Models: []config.ModelConfig{
			{ID: "m-lp-1", ProviderID: "p-lp-1"},
			{ID: "m-lp-2", ProviderID: "p-lp-2"},
		},
	}

	router := NewRouter(nil, nil)

	tests := []struct {
		name              string
		targets           []config.RouteTarget
		setupPending      func(r *Router)
		expectedTargetRef string
		expectError       bool
		allowRefs         []string
	}{
		{
			name:        "No targets",
			targets:     []config.RouteTarget{},
			expectError: true,
		},
		{
			name: "Single healthy target",
			targets: []config.RouteTarget{
				{Ref: "m-lp-1"},
			},
			setupPending:      func(r *Router) { r.pendingRequests = make(map[string]*int32) },
			expectedTargetRef: "m-lp-1",
		},
		{
			name: "One target less pending",
			targets: []config.RouteTarget{
				{Ref: "m-lp-1"},
				{Ref: "m-lp-2"},
			},
			setupPending: func(r *Router) {
				r.pendingRequests = make(map[string]*int32)
				r.IncrementPendingRequests("m-lp-1") // 1 pending
				// m-lp-2 has 0 pending
			},
			expectedTargetRef: "m-lp-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupPending != nil {
				tt.setupPending(router)
			}
			selected, err := router.selectTargetLeastPending(tt.targets, registry, runtimeCfg, config.ProtocolHTTPLLM)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, selected)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, selected)
				if len(tt.allowRefs) > 0 {
					assert.Contains(t, tt.allowRefs, selected.Ref)
				} else {
					assert.Equal(t, tt.expectedTargetRef, selected.Ref)
				}
			}
		})
	}
}

func TestMain(m *testing.M) {
	// Suppress log output during tests
	log.SetOutput(io.Discard)
	exitVal := m.Run()
	log.SetOutput(os.Stderr) // Restore log output
	os.Exit(exitVal)
}
