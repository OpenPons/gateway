package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/openpons/gateway/internal/config"
	// "github.com/openpons/gateway/internal/pluginruntime" // Not directly used by mock type signatures if PluginClient is from gwplugin
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/routing"
	gwplugin "github.com/openpons/gateway/pkg/plugin" // Import for PluginHookService
)

// --- Common Mocks for proxy package tests ---

// MockProviderAdapter
type MockProviderAdapter struct {
	ChatCompletionFunc       func(ctx context.Context, request *provider.ChatCompletionRequest) (*provider.ChatCompletionResponse, error)
	StreamChatCompletionFunc func(ctx context.Context, request *provider.ChatCompletionRequest, stream io.Writer) error
	ProviderInfoFunc         func() provider.Info
	GetConfigFunc            func() *config.ProviderConfig
	InitFunc                 func(cfg *config.ProviderConfig, sr provider.SecretRetriever) error
	ShutdownFunc             func() error
	HealthCheckFunc          func(ctx context.Context) error
	GenerateEmbeddingFunc    func(ctx context.Context, request *provider.EmbeddingRequest) (*provider.EmbeddingResponse, error)
	AudioTranscriptionFunc   func(ctx context.Context, request *provider.AudioTranscriptionRequest) (*provider.AudioTranscriptionResponse, error)
	TextToSpeechFunc         func(ctx context.Context, request *provider.TextToSpeechRequest, stream io.Writer) error
	InvokeToolFunc           func(ctx context.Context, request *provider.ToolInvocationRequest) (*provider.ToolInvocationResponse, error)
	StreamInvokeToolFunc     func(ctx context.Context, requestStream <-chan *provider.ToolInvocationStreamChunk, responseStream chan<- *provider.ToolInvocationStreamChunk) error
}

func (m *MockProviderAdapter) Init(cfg *config.ProviderConfig, sr provider.SecretRetriever) error {
	if m.InitFunc != nil {
		return m.InitFunc(cfg, sr)
	}
	return nil
}
func (m *MockProviderAdapter) ProviderInfo() provider.Info {
	if m.ProviderInfoFunc != nil {
		return m.ProviderInfoFunc()
	}
	return provider.Info{}
}
func (m *MockProviderAdapter) GetConfig() *config.ProviderConfig {
	if m.GetConfigFunc != nil {
		return m.GetConfigFunc()
	}
	return nil
}
func (m *MockProviderAdapter) ChatCompletion(ctx context.Context, request *provider.ChatCompletionRequest) (*provider.ChatCompletionResponse, error) {
	if m.ChatCompletionFunc != nil {
		return m.ChatCompletionFunc(ctx, request)
	}
	return nil, fmt.Errorf("ChatCompletionFunc not set")
}
func (m *MockProviderAdapter) StreamChatCompletion(ctx context.Context, request *provider.ChatCompletionRequest, stream io.Writer) error {
	if m.StreamChatCompletionFunc != nil {
		return m.StreamChatCompletionFunc(ctx, request, stream)
	}
	return fmt.Errorf("StreamChatCompletionFunc not set")
}
func (m *MockProviderAdapter) GenerateEmbedding(ctx context.Context, request *provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
	if m.GenerateEmbeddingFunc != nil {
		return m.GenerateEmbeddingFunc(ctx, request)
	}
	return nil, fmt.Errorf("GenerateEmbeddingFunc not set")
}
func (m *MockProviderAdapter) AudioTranscription(ctx context.Context, request *provider.AudioTranscriptionRequest) (*provider.AudioTranscriptionResponse, error) {
	if m.AudioTranscriptionFunc != nil {
		return m.AudioTranscriptionFunc(ctx, request)
	}
	return nil, fmt.Errorf("AudioTranscriptionFunc not set")
}
func (m *MockProviderAdapter) TextToSpeech(ctx context.Context, request *provider.TextToSpeechRequest, stream io.Writer) error {
	if m.TextToSpeechFunc != nil {
		return m.TextToSpeechFunc(ctx, request, stream)
	}
	return fmt.Errorf("TextToSpeechFunc not set")
}
func (m *MockProviderAdapter) InvokeTool(ctx context.Context, request *provider.ToolInvocationRequest) (*provider.ToolInvocationResponse, error) {
	if m.InvokeToolFunc != nil {
		return m.InvokeToolFunc(ctx, request)
	}
	return nil, fmt.Errorf("InvokeToolFunc not set")
}
func (m *MockProviderAdapter) StreamInvokeTool(ctx context.Context, requestStream <-chan *provider.ToolInvocationStreamChunk, responseStream chan<- *provider.ToolInvocationStreamChunk) error {
	if m.StreamInvokeToolFunc != nil {
		return m.StreamInvokeToolFunc(ctx, requestStream, responseStream)
	}
	return fmt.Errorf("StreamInvokeToolFunc not set")
}
func (m *MockProviderAdapter) HealthCheck(ctx context.Context) error {
	if m.HealthCheckFunc != nil {
		return m.HealthCheckFunc(ctx)
	}
	return nil
}
func (m *MockProviderAdapter) Shutdown() error {
	if m.ShutdownFunc != nil {
		return m.ShutdownFunc()
	}
	return nil
}

// MockRouter
type MockRouter struct {
	ResolveRouteFunc func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error)
}

func (m *MockRouter) ResolveRoute(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
	if m.ResolveRouteFunc != nil {
		return m.ResolveRouteFunc(ctx, reqCtx)
	}
	panic("MockRouter.ResolveRouteFunc not set")
}

// MockIAMService
type MockIAMService struct {
	// AuthenticateFunc is removed as it's not a direct method used by handlers and iam.Principal was undefined.
	CheckPermissionFunc func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool
	AuthMiddlewareFunc  func(next http.Handler) http.Handler
	AuthzMiddlewareFunc func(requiredPermission config.Permission) func(http.Handler) http.Handler
}

// Authenticate method removed.
func (m *MockIAMService) CheckPermission(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
	if m.CheckPermissionFunc != nil {
		return m.CheckPermissionFunc(ctx, principalID, authInfo, permission)
	}
	return true // Default mock behavior: allow all permissions
}

func (m *MockIAMService) AuthMiddleware(next http.Handler) http.Handler {
	if m.AuthMiddlewareFunc != nil {
		return m.AuthMiddlewareFunc(next)
	}
	// Default mock behavior: pass through, or simulate successful auth by adding mock principal to context
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Optionally, add a mock principal to context for downstream handlers if tests require it
		// For example:
		// mockPrincipalID := "test-mock-principal"
		// mockAuthInfo := "mock-auth-info" // Or a mock APIKey/JWTClaims struct
		// ctx := context.WithValue(r.Context(), iam.ContextKeyPrincipalID, mockPrincipalID)
		// ctx = context.WithValue(ctx, iam.ContextKeyAuthInfo, mockAuthInfo)
		// next.ServeHTTP(w, r.WithContext(ctx))
		next.ServeHTTP(w, r) // Simplest pass-through
	})
}

func (m *MockIAMService) AuthzMiddleware(requiredPermission config.Permission) func(http.Handler) http.Handler {
	if m.AuthzMiddlewareFunc != nil {
		return m.AuthzMiddlewareFunc(requiredPermission)
	}
	// Default mock behavior: pass through.
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// In a more complex mock, you might check if a mock principal exists
			// and if their mock permissions (if any) satisfy requiredPermission.
			next.ServeHTTP(w, r)
		})
	}
}

// MockPluginManager
type MockPluginManager struct {
	ExecutePreRequestHooksFunc  func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error)
	ExecutePostRequestHooksFunc func(ctx context.Context, route *config.RouteConfig, r *http.Request, responseBody interface{}) (interface{}, error)
	GetPluginClientFunc         func(pluginID string) (gwplugin.PluginHookService, error) // Corrected type
	ShutdownFunc                func()                                                    // Added
}

func (m *MockPluginManager) ExecutePreRequestHooks(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
	if m.ExecutePreRequestHooksFunc != nil {
		return m.ExecutePreRequestHooksFunc(ctx, route, r, requestBody)
	}
	return requestBody, nil
}
func (m *MockPluginManager) ExecutePostRequestHooks(ctx context.Context, route *config.RouteConfig, r *http.Request, responseBody interface{}) (interface{}, error) {
	if m.ExecutePostRequestHooksFunc != nil {
		return m.ExecutePostRequestHooksFunc(ctx, route, r, responseBody)
	}
	return responseBody, nil
}
func (m *MockPluginManager) GetPluginClient(pluginID string) (gwplugin.PluginHookService, error) { // Corrected type
	if m.GetPluginClientFunc != nil {
		return m.GetPluginClientFunc(pluginID)
	}
	return nil, fmt.Errorf("GetPluginClient not mocked")
}

func (m *MockPluginManager) Shutdown() {
	if m.ShutdownFunc != nil {
		m.ShutdownFunc()
	}
	// Default mock behavior: no-op
}
