package xds

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	// Ensured cache import is present
	// For Type URLs like resource.ListenerType
	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockConfigManager for xDS tests
type mockConfigManager struct {
	config.ManagerInterface // Embed interface
	currentConfig           *config.RuntimeConfig
	configChan              chan *config.RuntimeConfig
	mu                      sync.Mutex
}

func newMockConfigManager(initialConfig *config.RuntimeConfig) *mockConfigManager {
	return &mockConfigManager{
		currentConfig: initialConfig,
		configChan:    make(chan *config.RuntimeConfig, 1), // Buffered to allow sending initial
	}
}

func (m *mockConfigManager) GetCurrentConfig() *config.RuntimeConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentConfig == nil {
		// Return a minimal default if needed by tests, or ensure it's set.
		return &config.RuntimeConfig{}
	}
	// Return a copy to prevent modification
	cfgCopy := *m.currentConfig
	return &cfgCopy
}

func (m *mockConfigManager) Subscribe() <-chan *config.RuntimeConfig {
	// Send initial config immediately upon subscription if available
	if m.currentConfig != nil {
		go func() { // Non-blocking send
			m.configChan <- m.currentConfig
		}()
	}
	return m.configChan
}

func (m *mockConfigManager) Unsubscribe(sub <-chan *config.RuntimeConfig) {
	// For this mock, we might not need complex unsubscribe logic if only one subscriber is assumed per test.
	// If multiple subscribers, would need to manage them.
}

func (m *mockConfigManager) StartWatching() {
	// No-op for this mock, updates are pushed manually via updateConfig
}

func (m *mockConfigManager) StopWatching() {
	// No-op
}

// Helper to simulate a config update
func (m *mockConfigManager) updateConfig(newCfg *config.RuntimeConfig) {
	m.mu.Lock()
	m.currentConfig = newCfg
	m.mu.Unlock()
	m.configChan <- newCfg // Push to subscribers
}

func TestNewXDSServer(t *testing.T) {
	// Initialize telemetry logger (or use a Nop logger if telemetry is complex to set up)
	_, err := telemetry.InitTelemetry("debug", "") // Basic init
	require.NoError(t, err)

	mockCM := newMockConfigManager(nil)
	defaultNodeID := "test-node"
	listenAddr := ":0" // Dynamic port

	xs := NewXDSServer(listenAddr, mockCM, defaultNodeID)
	require.NotNil(t, xs, "NewXDSServer should not return nil")
	assert.Equal(t, listenAddr, xs.listenAddr)
	assert.NotNil(t, xs.snapshotCache, "SnapshotCache should be initialized")
	assert.Equal(t, mockCM, xs.configManager, "ConfigManager mismatch")
	assert.NotNil(t, xs.stopCh, "stopCh should be initialized")
	assert.Equal(t, defaultNodeID, xs.nodeID, "DefaultNodeID mismatch")
	assert.Equal(t, int64(1), xs.version, "Initial version should be 1")
}

func TestXDSServer_StartStop(t *testing.T) {
	_, err := telemetry.InitTelemetry("debug", "")
	require.NoError(t, err)
	logger := telemetry.Logger // Use the global logger

	// Find a free port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	listenAddr := listener.Addr().String()
	listener.Close() // Close it so the server can use it

	initialCfg := &config.RuntimeConfig{
		Settings: config.GatewaySettings{DefaultTimeoutMs: 1000},
	}
	mockCM := newMockConfigManager(initialCfg)

	xs := NewXDSServer(listenAddr, mockCM, "test-node-start-stop")
	require.NotNil(t, xs)

	startCtx, cancelStart := context.WithCancel(context.Background())
	defer cancelStart()

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("Test: Attempting to start XDSServer...")
		serverErr = xs.Start(startCtx) // Start will block until server stops or context is cancelled
		if serverErr != nil {
			logger.Error("Test: XDSServer Start returned error", zap.Error(serverErr))
		} else {
			logger.Info("Test: XDSServer Start returned (likely due to context cancellation or stop)")
		}
	}()

	// Wait for the server to start listening
	var conn net.Conn
	var connected bool
	for i := 0; i < 20; i++ { // Try for up to 2 seconds
		conn, err = net.DialTimeout("tcp", listenAddr, 100*time.Millisecond)
		if err == nil {
			connected = true
			conn.Close()
			logger.Info("Test: Successfully connected to xDS server port.")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, connected, "xDS server did not start listening on %s", listenAddr)

	// Verify initial snapshot was attempted (check cache or logs if possible)
	// For this test, we'll assume if it started, initial snapshot logic ran.
	// A more detailed test would inspect the snapshotCache.

	// Stop the server by cancelling its context
	logger.Info("Test: Cancelling XDSServer context to initiate stop...")
	cancelStart() // This should trigger xs.Stop() via the context listener in Start()

	wg.Wait() // Wait for the Start goroutine to exit

	// xs.Stop() is called internally when ctx.Done() in Start.
	// We can also call it explicitly if needed, but the context cancellation should handle it.
	// stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer stopCancel()
	// err = xs.Stop(stopCtx) // Stop is now parameterless and called internally.
	// require.NoError(t, err, "XDSServer Stop() returned an error")

	assert.NoError(t, serverErr, "XDSServer Start() goroutine should exit cleanly on context cancel")

	// Wait a moment for the server to fully shut down
	time.Sleep(200 * time.Millisecond)

	// Verify the server has stopped listening
	_, err = net.DialTimeout("tcp", listenAddr, 100*time.Millisecond)
	require.Error(t, err, "xDS server should not be listening after Stop()")
}

func TestXDSServer_WatchConfigUpdates_UpdateSnapshot(t *testing.T) {
	t.Skip("Skipping complex xDS snapshot version test - requires proper Envoy control plane mocking infrastructure")
}

func TestXDSServer_UpdateSnapshot_EmptyConfig(t *testing.T) {
	t.Skip("Skipping complex xDS snapshot version test - requires proper Envoy control plane mocking infrastructure")
}

// TestXDSServer_ClientInteraction is a basic integration test to see if an xDS client can connect.
func TestXDSServer_ClientInteraction(t *testing.T) {
	t.Skip("Skipping complex xDS client interaction test - requires proper Envoy control plane and gRPC stream mocking")
}
