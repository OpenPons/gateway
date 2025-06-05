package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	// "time" // Not directly used in this specific test logic, but provider.EmbeddingResponse might have time fields

	"github.com/go-chi/chi/v5"
	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam" // For iam.ContextKeyPrincipalID

	// For type casting in NewEmbeddingProxyHandler call
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Common Mocks (MockProviderAdapter, MockRouter, MockIAMService, MockPluginManager) are defined in proxy_test_helpers.go

// MockConfigManager (specific to this test file)
type MockConfigManager struct {
	GetCurrentConfigFunc func() *config.RuntimeConfig
	SubscribeFunc        func() <-chan *config.RuntimeConfig // Added
}

func (m *MockConfigManager) GetCurrentConfig() *config.RuntimeConfig { return m.GetCurrentConfigFunc() }

// Subscribe provides a dummy implementation for the interface.
func (m *MockConfigManager) Subscribe() <-chan *config.RuntimeConfig {
	if m.SubscribeFunc != nil {
		return m.SubscribeFunc()
	}
	// Return a closed channel or a nil channel if not used by handler
	// A closed channel is safer as reads won't block.
	ch := make(chan *config.RuntimeConfig)
	close(ch)
	return ch
}

// WatchForChanges and LoadInitialConfig are likely not part of ManagerInterface anymore.
// If they are, they need to be implemented or the interface updated.
// Assuming they are not part of the current ManagerInterface based on previous changes.
// func (m *MockConfigManager) WatchForChanges(ctx context.Context, callback func(*config.RuntimeConfig)) {}
// func (m *MockConfigManager) LoadInitialConfig(configPath string) error { return nil }

// MockProviderRegistry (specific to this test file)
type MockProviderRegistry struct {
	GetAdapterFunc func(providerID string) (provider.ProviderAdapter, error)
}

func (m *MockProviderRegistry) GetAdapter(providerID string) (provider.ProviderAdapter, error) {
	if m.GetAdapterFunc != nil {
		return m.GetAdapterFunc(providerID)
	}
	return nil, fmt.Errorf("GetAdapterFunc not set on MockProviderRegistry")
}
func (m *MockProviderRegistry) InitializeAdapters(cfg *config.RuntimeConfig, sm provider.SecretRetriever) {
}
func (m *MockProviderRegistry) ShutdownAdapters() {}

func TestNewEmbeddingProxyHandler(t *testing.T) {
	t.Skip("Skipping TestNewEmbeddingProxyHandler: This test would require more complex setup or SUT refactoring if NewEmbeddingProxyHandler itself had more logic beyond field assignment.")
}

func TestEmbeddingProxyHandler_ServeHTTP_Successful(t *testing.T) {
	mockAdapter := &MockProviderAdapter{}   // From proxy_test_helpers.go
	mockRouter := &MockRouter{}             // From proxy_test_helpers.go
	mockIAM := &MockIAMService{}            // From proxy_test_helpers.go
	mockPM := &MockPluginManager{}          // From proxy_test_helpers.go
	mockCfgMgr := &MockConfigManager{}      // Local mock
	mockRegistry := &MockProviderRegistry{} // Local mock
	logger := zap.NewNop()

	// NewEmbeddingProxyHandler now accepts interfaces.
	handler := NewEmbeddingProxyHandler(
		mockCfgMgr,
		mockIAM,
		mockRouter,
		mockRegistry, // Pass the mockRegistry
		mockPM,
		logger,
	)

	chiRouter := chi.NewRouter()
	chiRouter.Post("/proxy/models/{modelID}/embeddings", handler.ServeHTTP)
	testServer := httptest.NewServer(chiRouter)
	defer testServer.Close()

	t.Run("Successful embedding generation", func(t *testing.T) {
		modelID := "text-embed-ada"
		upstreamModelName := "text-embedding-ada-002"
		providerID := "p-embed"

		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{
				Models: []config.ModelConfig{
					{ID: modelID, ProviderID: providerID, UpstreamModelName: upstreamModelName},
				},
			}
		}

		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			assert.Equal(t, modelID, reqCtx.ModelID)
			return &routing.ResolvedTarget{
				Adapter: mockAdapter,
				Route:   &config.RouteConfig{ID: "route-embed"},
				Target:  &config.RouteTarget{Ref: modelID}, // Target.Ref should be the ModelConfig.ID
			}, nil
		}

		// This mock is for the provider.RegistryInterface, not the adapter itself.
		// The router resolves the adapter, so this mock might not be directly called by EmbeddingProxyHandler
		// if the adapter is already part of ResolvedTarget.
		// However, if EmbeddingProxyHandler were to use providerRegistry directly, this would be needed.
		// For now, let's assume resolvedTarget.Adapter is used.
		mockRegistry.GetAdapterFunc = func(pid string) (provider.ProviderAdapter, error) {
			if pid == providerID {
				return mockAdapter, nil
			}
			return nil, fmt.Errorf("unexpected providerID for mockRegistry: %s", pid)
		}

		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			assert.Equal(t, "test-user-id", principalID)
			assert.Equal(t, config.Permission("proxy:embeddings:invoke"), permission)
			return true
		}

		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil
		}
		mockPM.ExecutePostRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, responseBody interface{}) (interface{}, error) {
			return responseBody, nil
		}

		mockAdapter.GenerateEmbeddingFunc = func(ctx context.Context, request *provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
			assert.Equal(t, upstreamModelName, request.Model)
			assert.Equal(t, "test input", request.Input.(string)) // Assuming input is string
			return &provider.EmbeddingResponse{
				Object: "list",
				Data:   []provider.Embedding{{Object: "embedding", Embedding: []float32{0.1, 0.2}, Index: 0}},
				Model:  upstreamModelName, // Provider responds with the upstream model name it used
			}, nil
		}
		// GetConfig is called by the handler for logging purposes.
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: providerID}
		}

		reqInput := "test input"
		reqBody := provider.EmbeddingRequest{Input: reqInput, Model: modelID}
		reqBodyBytes, _ := json.Marshal(reqBody)

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")

		url := fmt.Sprintf("%s/proxy/models/%s/embeddings", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var respData provider.EmbeddingResponse
		err = json.NewDecoder(rr.Body).Decode(&respData)
		require.NoError(t, err)
		assert.Equal(t, "list", respData.Object)
		require.Len(t, respData.Data, 1)
		assert.Equal(t, []float32{0.1, 0.2}, respData.Data[0].Embedding)
		assert.Equal(t, upstreamModelName, respData.Model)
	})

	t.Run("Route resolution failure", func(t *testing.T) {
		modelID := "test-model-route-fail"

		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			assert.Equal(t, modelID, reqCtx.ModelID)
			return nil, fmt.Errorf("no matching route found: mock route resolution error") // Ensure error triggers 404
		}

		// IAM and other mocks don't need specific setup as routing fails first.

		reqBody := provider.EmbeddingRequest{Input: "test input", Model: modelID}
		reqBodyBytes, _ := json.Marshal(reqBody)

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")

		url := fmt.Sprintf("%s/proxy/models/%s/embeddings", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "No route found for the request: no matching route found: mock route resolution error")
	})

	t.Run("IAM permission denied", func(t *testing.T) {
		modelID := "test-model-iam-fail"
		providerID := "p-iam-fail"

		// Configure mockRouter to successfully resolve a route
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			assert.Equal(t, modelID, reqCtx.ModelID)
			return &routing.ResolvedTarget{
				Adapter: mockAdapter, // Re-use mockAdapter from outer scope
				Route:   &config.RouteConfig{ID: "route-iam"},
				Target:  &config.RouteTarget{Ref: modelID},
			}, nil
		}

		// Configure mockIAM to deny permission
		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			assert.Equal(t, "test-user-id", principalID)
			// The permission string for embeddings is "proxy:embeddings:invoke" in EmbeddingProxyHandler
			// but the handler actually constructs it as "proxy:invoke:audiotranscription:%s" or "proxy:invoke:texttospeech:%s"
			// This needs to be consistent. For embeddings, it's "proxy:embeddings:invoke".
			// The SUT (EmbeddingProxyHandler) uses: requiredPermission := config.Permission("proxy:embeddings:invoke")
			assert.Equal(t, config.Permission("proxy:embeddings:invoke"), permission)
			return false // Deny permission
		}

		// mockAdapter.GetConfigFunc is needed by the handler for logging if route resolution succeeds
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: providerID}
		}

		reqBody := provider.EmbeddingRequest{Input: "test input", Model: modelID}
		reqBodyBytes, _ := json.Marshal(reqBody)

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")

		url := fmt.Sprintf("%s/proxy/models/%s/embeddings", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "Forbidden: You do not have permission to perform this action.")
	})

	t.Run("Provider error during embedding generation", func(t *testing.T) {
		modelID := "text-embed-ada-provider-fail"
		upstreamModelName := "text-embedding-ada-002-pf"
		providerID := "p-embed-pf"

		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{
				Models: []config.ModelConfig{
					{ID: modelID, ProviderID: providerID, UpstreamModelName: upstreamModelName},
				},
			}
		}

		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			assert.Equal(t, modelID, reqCtx.ModelID)
			return &routing.ResolvedTarget{
				Adapter: mockAdapter,
				Route:   &config.RouteConfig{ID: "route-provider-fail"},
				Target:  &config.RouteTarget{Ref: modelID},
			}, nil
		}

		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			return true // Grant permission
		}

		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil // No error, pass through
		}

		// mockAdapter.GetConfigFunc is needed by the handler for logging
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: providerID}
		}
		mockAdapter.GenerateEmbeddingFunc = func(ctx context.Context, request *provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
			assert.Equal(t, upstreamModelName, request.Model)
			return nil, fmt.Errorf("mock provider GenerateEmbedding error") // Simulate provider error
		}

		reqBody := provider.EmbeddingRequest{Input: "test input", Model: modelID}
		reqBodyBytes, _ := json.Marshal(reqBody)

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")

		url := fmt.Sprintf("%s/proxy/models/%s/embeddings", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		// Check for a 5xx error. The exact code depends on mapProviderErrorToHTTPStatus.
		// Let's assume a generic 500 or 502/503. The SUT uses mapProviderErrorToHTTPStatus.
		// For a generic error, it might default to 500.
		// The current mapProviderErrorToHTTPStatus in chat_handler.go defaults to http.StatusServiceUnavailable (503)
		// if no specific mapping. Let's assume embedding_handler.go has similar or will add it.
		// For now, checking for 500 as a general server-side error from provider.
		// The actual error message from SUT: "Failed to generate embedding"
		// The mapProviderErrorToHTTPStatus in embedding_handler.go defaults to http.StatusInternalServerError (500)
		// and uses the default message "Failed to generate embedding". http.Error adds a newline.
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Equal(t, "Failed to generate embedding\n", rr.Body.String())
	})

	t.Run("Bad request body", func(t *testing.T) {
		modelID := "test-model-bad-request"
		// No need to set up all mocks as it should fail early

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/embeddings", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBufferString("this is not json"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})

	t.Run("Pre-request hook error", func(t *testing.T) {
		modelID := "test-model-pre-hook-fail"
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return &routing.ResolvedTarget{Adapter: mockAdapter, Route: &config.RouteConfig{}, Target: &config.RouteTarget{Ref: modelID}}, nil
		}
		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			return true
		}
		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return nil, fmt.Errorf("pre-hook error")
		}
		// Mock GetConfig as it's called for logging when an error occurs
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: "mockProviderID", Name: "MockProvider"}
		}

		reqBody := provider.EmbeddingRequest{Input: "test input", Model: modelID}
		reqBodyBytes, _ := json.Marshal(reqBody)
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/embeddings", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), "Error in pre-request plugin")
	})

	t.Run("Post-request hook error", func(t *testing.T) {
		modelID := "test-model-post-hook-fail"
		upstreamModelName := "text-embedding-ada-002-phf"
		providerID := "p-embed-phf"

		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{
				Models: []config.ModelConfig{{ID: modelID, ProviderID: providerID, UpstreamModelName: upstreamModelName}},
			}
		}
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return &routing.ResolvedTarget{Adapter: mockAdapter, Route: &config.RouteConfig{}, Target: &config.RouteTarget{Ref: modelID}}, nil
		}
		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			return true
		}
		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil
		}
		mockAdapter.GenerateEmbeddingFunc = func(ctx context.Context, request *provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
			return &provider.EmbeddingResponse{Data: []provider.Embedding{{Embedding: []float32{0.1}}}}, nil
		}
		mockPM.ExecutePostRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, responseBody interface{}) (interface{}, error) {
			return nil, fmt.Errorf("post-hook error")
		}
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: providerID}
		}

		reqBody := provider.EmbeddingRequest{Input: "test input", Model: modelID}
		reqBodyBytes, _ := json.Marshal(reqBody)
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/embeddings", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		// Post-request hook errors are logged but don't fail the request in the current implementation
		var respData provider.EmbeddingResponse
		err = json.NewDecoder(rr.Body).Decode(&respData)
		require.NoError(t, err)
	})
}
