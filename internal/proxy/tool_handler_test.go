package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam"
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/routing"
	"github.com/openpons/gateway/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Local Mocks for tool_handler_test.go
type MockToolConfigManager struct {
	GetCurrentConfigFunc func() *config.RuntimeConfig
	SubscribeFunc        func() <-chan *config.RuntimeConfig // Added
}

func (m *MockToolConfigManager) GetCurrentConfig() *config.RuntimeConfig {
	return m.GetCurrentConfigFunc()
}

// Subscribe provides a dummy implementation for the interface.
func (m *MockToolConfigManager) Subscribe() <-chan *config.RuntimeConfig {
	if m.SubscribeFunc != nil {
		return m.SubscribeFunc()
	}
	ch := make(chan *config.RuntimeConfig)
	close(ch)
	return ch
}

// Assuming WatchForChanges and LoadInitialConfig are not part of the current ManagerInterface
// func (m *MockToolConfigManager) WatchForChanges(ctx context.Context, callback func(*config.RuntimeConfig)) {}
// func (m *MockToolConfigManager) LoadInitialConfig(configPath string) error { return nil }

type MockToolProviderRegistry struct {
	GetAdapterFunc func(providerID string) (provider.ProviderAdapter, error)
}

func (m *MockToolProviderRegistry) GetAdapter(providerID string) (provider.ProviderAdapter, error) {
	if m.GetAdapterFunc != nil {
		return m.GetAdapterFunc(providerID)
	}
	return nil, fmt.Errorf("GetAdapterFunc not set on MockToolProviderRegistry")
}
func (m *MockToolProviderRegistry) InitializeAdapters(cfg *config.RuntimeConfig, sm provider.SecretRetriever) {
}
func (m *MockToolProviderRegistry) ShutdownAdapters() {}

func TestToolProxyHandler_ServeHTTP(t *testing.T) {
	telemetry.Logger = zap.NewNop()

	t.Run("Successful tool invocation", func(t *testing.T) {
		// Create separate mock instances for this test
		mockAdapter := &MockProviderAdapter{}
		mockRouter := &MockRouter{}
		mockIAM := &MockIAMService{}
		mockPM := &MockPluginManager{}
		mockCfgMgr := &MockToolConfigManager{}
		mockRegistry := &MockToolProviderRegistry{}

		toolHandler := NewToolProxyHandler(
			mockCfgMgr, mockIAM, mockRouter, mockRegistry, mockPM, zap.NewNop(),
		)

		chiRouter := chi.NewRouter()
		chiRouter.Post("/proxy/tools/{toolID}/invoke", toolHandler.ServeHTTP)
		testServer := httptest.NewServer(chiRouter)
		defer testServer.Close()

		toolID := "calculator"              // User-facing ToolConfig.ID
		upstreamToolName := "calculator_v1" // ToolConfig.UpstreamToolName
		providerID := "p-mcp-server-1"      // ToolConfig.ProviderID

		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{
				Tools: []config.ToolConfig{
					{ID: toolID, ProviderID: providerID, UpstreamToolName: upstreamToolName, SupportsStreaming: false},
				},
			}
		}

		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			assert.Equal(t, toolID, reqCtx.ToolID)
			return &routing.ResolvedTarget{
				Adapter: mockAdapter,
				Route:   &config.RouteConfig{ID: "route-tool"},
				Target:  &config.RouteTarget{Ref: toolID},
			}, nil
		}

		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			assert.Equal(t, "test-user-id", principalID)
			assert.Equal(t, config.Permission(fmt.Sprintf("proxy:invoke:tool:%s", toolID)), permission)
			return true
		}

		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil
		}
		mockPM.ExecutePostRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, responseBody interface{}) (interface{}, error) {
			return responseBody, nil
		}

		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: providerID, Type: config.ProviderTypeToolServer}
		}
		mockAdapter.InvokeToolFunc = func(ctx context.Context, request *provider.ToolInvocationRequest) (*provider.ToolInvocationResponse, error) {
			assert.Equal(t, upstreamToolName, request.ToolName)
			argsBytes, err := json.Marshal(request.Arguments)
			require.NoError(t, err)
			assert.JSONEq(t, `{"arg1":"val1"}`, string(argsBytes))
			return &provider.ToolInvocationResponse{
				Result: json.RawMessage(`{"output":"result1"}`),
			}, nil
		}

		reqPayload := provider.ToolInvocationRequest{
			ToolName:  toolID,
			Arguments: map[string]interface{}{"arg1": "val1"},
		}
		reqBodyBytes, _ := json.Marshal(reqPayload)

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		urlPath := fmt.Sprintf("%s/proxy/tools/%s/invoke", testServer.URL, toolID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", urlPath, bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var respData provider.ToolInvocationResponse
		err = json.NewDecoder(rr.Body).Decode(&respData)
		require.NoError(t, err)
		resultBytes, err := json.Marshal(respData.Result)
		require.NoError(t, err)
		assert.JSONEq(t, `{"output":"result1"}`, string(resultBytes))
	})

	t.Run("ToolConfig not found", func(t *testing.T) {
		// Create separate mock instances for this test
		mockAdapter := &MockProviderAdapter{}
		mockRouter := &MockRouter{}
		mockIAM := &MockIAMService{}
		mockPM := &MockPluginManager{}
		mockCfgMgr := &MockToolConfigManager{}
		mockRegistry := &MockToolProviderRegistry{}

		toolHandler := NewToolProxyHandler(
			mockCfgMgr, mockIAM, mockRouter, mockRegistry, mockPM, zap.NewNop(),
		)

		chiRouter := chi.NewRouter()
		chiRouter.Post("/proxy/tools/{toolID}/invoke", toolHandler.ServeHTTP)
		testServer := httptest.NewServer(chiRouter)
		defer testServer.Close()

		toolID := "nonexistent-tool"
		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{Tools: []config.ToolConfig{}} // No tools configured
		}

		// The handler resolves route first, then looks for ToolConfig, so we need a successful route resolution
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: "test-provider", Type: config.ProviderTypeToolServer}
		}
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return &routing.ResolvedTarget{
				Adapter: mockAdapter,
				Route:   &config.RouteConfig{ID: "route-tool"},
				Target:  &config.RouteTarget{Ref: toolID}, // This ref won't be found in ToolConfigs
			}, nil
		}

		reqPayload := provider.ToolInvocationRequest{ToolName: toolID, Arguments: map[string]interface{}{}}
		reqBodyBytes, _ := json.Marshal(reqPayload)
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		urlPath := fmt.Sprintf("%s/proxy/tools/%s/invoke", testServer.URL, toolID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", urlPath, bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), "Tool configuration missing for resolved route")
	})

	t.Run("Route resolution failure", func(t *testing.T) {
		// Create separate mock instances for this test
		mockRouter := &MockRouter{}
		mockIAM := &MockIAMService{}
		mockPM := &MockPluginManager{}
		mockCfgMgr := &MockToolConfigManager{}
		mockRegistry := &MockToolProviderRegistry{}

		toolHandler := NewToolProxyHandler(
			mockCfgMgr, mockIAM, mockRouter, mockRegistry, mockPM, zap.NewNop(),
		)

		chiRouter := chi.NewRouter()
		chiRouter.Post("/proxy/tools/{toolID}/invoke", toolHandler.ServeHTTP)
		testServer := httptest.NewServer(chiRouter)
		defer testServer.Close()

		toolID := "tool-route-fail"
		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{Tools: []config.ToolConfig{{ID: toolID, ProviderID: "p1", UpstreamToolName: "up-tool"}}}
		}
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return nil, fmt.Errorf("mock route resolution error")
		}

		reqPayload := provider.ToolInvocationRequest{ToolName: toolID, Arguments: map[string]interface{}{}}
		reqBodyBytes, _ := json.Marshal(reqPayload)
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		urlPath := fmt.Sprintf("%s/proxy/tools/%s/invoke", testServer.URL, toolID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", urlPath, bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "Tool route not found or routing error: mock route resolution error")
	})

	t.Run("Permission denied", func(t *testing.T) {
		// Create separate mock instances for this test
		mockAdapter := &MockProviderAdapter{}
		mockRouter := &MockRouter{}
		mockIAM := &MockIAMService{}
		mockPM := &MockPluginManager{}
		mockCfgMgr := &MockToolConfigManager{}
		mockRegistry := &MockToolProviderRegistry{}

		toolHandler := NewToolProxyHandler(
			mockCfgMgr, mockIAM, mockRouter, mockRegistry, mockPM, zap.NewNop(),
		)

		chiRouter := chi.NewRouter()
		chiRouter.Post("/proxy/tools/{toolID}/invoke", toolHandler.ServeHTTP)
		testServer := httptest.NewServer(chiRouter)
		defer testServer.Close()

		toolID := "tool-iam-fail"
		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{Tools: []config.ToolConfig{{ID: toolID, ProviderID: "p1", UpstreamToolName: "up-tool"}}}
		}
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return &routing.ResolvedTarget{Adapter: mockAdapter, Route: &config.RouteConfig{}, Target: &config.RouteTarget{Ref: toolID}}, nil
		}
		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			return false // Deny permission
		}
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig { // Called for logging
			return &config.ProviderConfig{ID: "p1", Type: config.ProviderTypeToolServer}
		}

		reqPayload := provider.ToolInvocationRequest{ToolName: toolID, Arguments: map[string]interface{}{}}
		reqBodyBytes, _ := json.Marshal(reqPayload)
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		urlPath := fmt.Sprintf("%s/proxy/tools/%s/invoke", testServer.URL, toolID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", urlPath, bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "Forbidden")
	})

	t.Run("Adapter InvokeTool error", func(t *testing.T) {
		// Create separate mock instances for this test
		mockAdapter := &MockProviderAdapter{}
		mockRouter := &MockRouter{}
		mockIAM := &MockIAMService{}
		mockPM := &MockPluginManager{}
		mockCfgMgr := &MockToolConfigManager{}
		mockRegistry := &MockToolProviderRegistry{}

		toolHandler := NewToolProxyHandler(
			mockCfgMgr, mockIAM, mockRouter, mockRegistry, mockPM, zap.NewNop(),
		)

		chiRouter := chi.NewRouter()
		chiRouter.Post("/proxy/tools/{toolID}/invoke", toolHandler.ServeHTTP)
		testServer := httptest.NewServer(chiRouter)
		defer testServer.Close()

		toolID := "tool-adapter-fail"
		providerID := "p-adapter-fail"
		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{Tools: []config.ToolConfig{{ID: toolID, ProviderID: providerID, UpstreamToolName: "up-tool"}}}
		}
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return &routing.ResolvedTarget{Adapter: mockAdapter, Route: &config.RouteConfig{}, Target: &config.RouteTarget{Ref: toolID}}, nil
		}
		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			return true
		}
		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil
		}
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: providerID, Type: config.ProviderTypeToolServer}
		}
		mockAdapter.InvokeToolFunc = func(ctx context.Context, request *provider.ToolInvocationRequest) (*provider.ToolInvocationResponse, error) {
			return nil, fmt.Errorf("adapter InvokeTool error")
		}

		reqPayload := provider.ToolInvocationRequest{ToolName: toolID, Arguments: map[string]interface{}{}}
		reqBodyBytes, _ := json.Marshal(reqPayload)
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		urlPath := fmt.Sprintf("%s/proxy/tools/%s/invoke", testServer.URL, toolID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", urlPath, bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code) // mapProviderErrorToHTTPStatus default is 500
		assert.Contains(t, rr.Body.String(), "Failed to invoke tool")
	})

	t.Run("Bad request body", func(t *testing.T) {
		// Create separate mock instances for this test
		mockRouter := &MockRouter{}
		mockIAM := &MockIAMService{}
		mockPM := &MockPluginManager{}
		mockCfgMgr := &MockToolConfigManager{}
		mockRegistry := &MockToolProviderRegistry{}

		toolHandler := NewToolProxyHandler(
			mockCfgMgr, mockIAM, mockRouter, mockRegistry, mockPM, zap.NewNop(),
		)

		chiRouter := chi.NewRouter()
		chiRouter.Post("/proxy/tools/{toolID}/invoke", toolHandler.ServeHTTP)
		testServer := httptest.NewServer(chiRouter)
		defer testServer.Close()

		toolID := "tool-bad-request"

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		urlPath := fmt.Sprintf("%s/proxy/tools/%s/invoke", testServer.URL, toolID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", urlPath, bytes.NewBufferString("not a valid json"))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})
}
