package provider

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/secrets"
	"github.com/openpons/gateway/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockLLMAdapter is a mock implementation of LLMAdapter for registry tests.
type MockLLMAdapter struct {
	mock.Mock
	name string // Can be set for default Name() if not mocked
	cfg  *config.ProviderConfig
}

func (m *MockLLMAdapter) Init(cfg *config.ProviderConfig, sm SecretRetriever) error {
	args := m.Called(cfg, sm)
	m.cfg = cfg
	// Simulate secret retrieval for GetConfig if necessary, or assume Init handles it
	if cfg != nil && cfg.CredentialsSecretID != "" && sm != nil {
		// This part is tricky as Init is mocked. If GetConfig needs secretVal,
		// the test setting up the mock for Init should also ensure GetConfig can work.
	}
	return args.Error(0)
}

func (m *MockLLMAdapter) ProviderInfo() Info {
	args := m.Called()
	if len(args) > 0 && args.Get(0) != nil {
		if info, ok := args.Get(0).(Info); ok {
			return info
		}
	}
	return Info{Name: m.name, Type: config.ProviderTypeLLM, Capabilities: []string{"chat_completion", "embedding"}}
}

func (m *MockLLMAdapter) GetConfig() *config.ProviderConfig {
	args := m.Called()
	if len(args) > 0 && args.Get(0) != nil {
		if cfg, ok := args.Get(0).(*config.ProviderConfig); ok {
			return cfg
		}
	}
	return m.cfg
}

func (m *MockLLMAdapter) ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ChatCompletionResponse), args.Error(1)
}

func (m *MockLLMAdapter) StreamChatCompletion(ctx context.Context, req *ChatCompletionRequest, stream io.Writer) error {
	args := m.Called(ctx, req, stream)
	if data, ok := args.Get(0).([]byte); ok && data != nil {
		_, err := stream.Write(data)
		if err != nil {
			return err
		}
	}
	return args.Error(1)
}

func (m *MockLLMAdapter) GenerateEmbedding(ctx context.Context, req *EmbeddingRequest) (*EmbeddingResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*EmbeddingResponse), args.Error(1)
}

func (m *MockLLMAdapter) AudioTranscription(ctx context.Context, req *AudioTranscriptionRequest) (*AudioTranscriptionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AudioTranscriptionResponse), args.Error(1)
}

func (m *MockLLMAdapter) TextToSpeech(ctx context.Context, req *TextToSpeechRequest, stream io.Writer) error {
	args := m.Called(ctx, req, stream)
	if data, ok := args.Get(0).([]byte); ok && data != nil {
		_, err := stream.Write(data)
		if err != nil {
			return err
		}
	}
	return args.Error(1)
}

func (m *MockLLMAdapter) InvokeTool(ctx context.Context, req *ToolInvocationRequest) (*ToolInvocationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ToolInvocationResponse), args.Error(1)
}

func (m *MockLLMAdapter) StreamInvokeTool(ctx context.Context, reqStream <-chan *ToolInvocationStreamChunk, respStream chan<- *ToolInvocationStreamChunk) error {
	args := m.Called(ctx, reqStream, respStream)
	if mockResponses, ok := args.Get(0).([]*ToolInvocationStreamChunk); ok && mockResponses != nil {
		go func() {
			defer close(respStream)
			for _, resp := range mockResponses {
				select {
				case respStream <- resp:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return args.Error(1)
}

func (m *MockLLMAdapter) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockLLMAdapter) Shutdown() error {
	args := m.Called()
	return args.Error(0)
}

// MockToolAdapter is a mock implementation of ToolAdapter for registry tests.
type MockToolAdapter struct {
	mock.Mock
	name string
	cfg  *config.ProviderConfig
}

func (m *MockToolAdapter) Init(cfg *config.ProviderConfig, sm SecretRetriever) error {
	args := m.Called(cfg, sm)
	m.cfg = cfg
	return args.Error(0)
}

func (m *MockToolAdapter) ProviderInfo() Info {
	args := m.Called()
	if len(args) > 0 && args.Get(0) != nil {
		if info, ok := args.Get(0).(Info); ok {
			return info
		}
	}
	return Info{Name: m.name, Type: config.ProviderTypeToolServer, Capabilities: []string{"invoke_tool"}}
}

func (m *MockToolAdapter) GetConfig() *config.ProviderConfig {
	args := m.Called()
	if len(args) > 0 && args.Get(0) != nil {
		if cfg, ok := args.Get(0).(*config.ProviderConfig); ok {
			return cfg
		}
	}
	return m.cfg
}

func (m *MockToolAdapter) ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ChatCompletionResponse), args.Error(1)
}

func (m *MockToolAdapter) StreamChatCompletion(ctx context.Context, req *ChatCompletionRequest, stream io.Writer) error {
	args := m.Called(ctx, req, stream)
	if data, ok := args.Get(0).([]byte); ok && data != nil {
		_, err := stream.Write(data)
		if err != nil {
			return err
		}
	}
	return args.Error(1)
}

func (m *MockToolAdapter) GenerateEmbedding(ctx context.Context, req *EmbeddingRequest) (*EmbeddingResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*EmbeddingResponse), args.Error(1)
}

func (m *MockToolAdapter) AudioTranscription(ctx context.Context, req *AudioTranscriptionRequest) (*AudioTranscriptionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AudioTranscriptionResponse), args.Error(1)
}

func (m *MockToolAdapter) TextToSpeech(ctx context.Context, req *TextToSpeechRequest, stream io.Writer) error {
	args := m.Called(ctx, req, stream)
	if data, ok := args.Get(0).([]byte); ok && data != nil {
		_, err := stream.Write(data)
		if err != nil {
			return err
		}
	}
	return args.Error(1)
}

func (m *MockToolAdapter) InvokeTool(ctx context.Context, req *ToolInvocationRequest) (*ToolInvocationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ToolInvocationResponse), args.Error(1)
}

func (m *MockToolAdapter) StreamInvokeTool(ctx context.Context, reqStream <-chan *ToolInvocationStreamChunk, respStream chan<- *ToolInvocationStreamChunk) error {
	args := m.Called(ctx, reqStream, respStream)
	if mockResponses, ok := args.Get(0).([]*ToolInvocationStreamChunk); ok && mockResponses != nil {
		go func() {
			defer close(respStream)
			for _, resp := range mockResponses {
				select {
				case respStream <- resp:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return args.Error(1)
}
func (m *MockToolAdapter) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *MockToolAdapter) Shutdown() error {
	args := m.Called()
	return args.Error(0)
}

// MockA2APlatformAdapter is a mock implementation of A2APlatformAdapter for registry tests.
type MockA2APlatformAdapter struct {
	mock.Mock
	name string
	cfg  *config.ProviderConfig
}

func (m *MockA2APlatformAdapter) Init(cfg *config.ProviderConfig, sm SecretRetriever) error {
	args := m.Called(cfg, sm)
	m.cfg = cfg
	return args.Error(0)
}

func (m *MockA2APlatformAdapter) ProviderInfo() Info {
	args := m.Called()
	if len(args) > 0 && args.Get(0) != nil {
		if info, ok := args.Get(0).(Info); ok {
			return info
		}
	}
	return Info{Name: m.name, Type: config.ProviderTypeAgentPlatform, Capabilities: []string{"invoke_agent"}}
}

func (m *MockA2APlatformAdapter) GetConfig() *config.ProviderConfig {
	args := m.Called()
	if len(args) > 0 && args.Get(0) != nil {
		if cfg, ok := args.Get(0).(*config.ProviderConfig); ok {
			return cfg
		}
	}
	return m.cfg
}

func (m *MockA2APlatformAdapter) InvokeAgent(ctx context.Context, req *AgentInvocationRequest) (*AgentInvocationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AgentInvocationResponse), args.Error(1)
}

func (m *MockA2APlatformAdapter) StreamInvokeAgent(ctx context.Context, reqStream <-chan *AgentInvocationStreamChunk, respStream chan<- *AgentInvocationStreamChunk) error {
	args := m.Called(ctx, reqStream, respStream)
	if mockResponses, ok := args.Get(0).([]*AgentInvocationStreamChunk); ok && mockResponses != nil {
		go func() {
			defer close(respStream)
			for _, resp := range mockResponses {
				select {
				case respStream <- resp:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return args.Error(1)
}

func (m *MockA2APlatformAdapter) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *MockA2APlatformAdapter) Shutdown() error {
	args := m.Called()
	return args.Error(0)
}

// MockSecretManagerForRegistry implements SecretRetriever for registry tests
type MockSecretManagerForRegistry struct{}

func (msm *MockSecretManagerForRegistry) GetSecret(ctx context.Context, id string) (string, error) {
	if id == "valid-secret" || id == "openai-secret" {
		return "secret-value", nil
	}
	return "", fmt.Errorf("secret '%s' not found", id)
}
func (msm *MockSecretManagerForRegistry) StoreSecret(ctx context.Context, id string, value string) error {
	return nil
}
func (msm *MockSecretManagerForRegistry) DeleteSecret(ctx context.Context, id string) error {
	return nil
}
func (msm *MockSecretManagerForRegistry) CreateSecret(ctx context.Context, name, secretType, value, providerID string) (string, error) {
	return "mock-secret-id", nil
}
func (msm *MockSecretManagerForRegistry) ListSecretsMetadata(ctx context.Context) ([]secrets.SecretMetadata, error) {
	return nil, nil
}

func TestNewRegistry(t *testing.T) {
	mockStore := &MockStoreForSecrets{}
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	realSm, err := secrets.NewSecretManager(mockStore, hexKey, "local", nil)
	require.NoError(t, err)

	registry := NewRegistry(realSm)
	require.NotNil(t, registry)
	assert.NotNil(t, registry.adapters)
	assert.NotNil(t, registry.secretManager)
}

// MockStoreForSecrets for initializing a real secrets.SecretManager
type MockStoreForSecrets struct {
	mock.Mock
	data map[string][]byte // Keep for simple Get/Set if not overridden by mock expectations
}

func NewMockStoreForSecrets() *MockStoreForSecrets {
	return &MockStoreForSecrets{data: make(map[string][]byte)}
}

func (s *MockStoreForSecrets) Get(ctx context.Context, key string) ([]byte, error) {
	args := s.Called(ctx, key)
	if args.Get(0) != nil {
		return args.Get(0).([]byte), args.Error(1)
	}
	// Fallback to simple map if not mocked, or remove this for strict mocking
	val, ok := s.data[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return val, nil
}

func (s *MockStoreForSecrets) Set(ctx context.Context, key string, value []byte) error {
	args := s.Called(ctx, key, value)
	// Fallback to simple map if not mocked, or remove this for strict mocking
	if s.data == nil {
		s.data = make(map[string][]byte)
	}
	s.data[key] = value
	return args.Error(0)
}

func (s *MockStoreForSecrets) Delete(ctx context.Context, key string) error {
	args := s.Called(ctx, key)
	// Fallback to simple map if not mocked, or remove this for strict mocking
	delete(s.data, key)
	return args.Error(0)
}

func (s *MockStoreForSecrets) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	args := s.Called(ctx, prefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string][]byte), args.Error(1)
}

func (s *MockStoreForSecrets) Watch(ctx context.Context, keyPrefix string) (<-chan store.WatchEvent, error) {
	args := s.Called(ctx, keyPrefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(<-chan store.WatchEvent), args.Error(1)
}

func (s *MockStoreForSecrets) Close() error {
	args := s.Called()
	return args.Error(0)
}

func (s *MockStoreForSecrets) BeginTransaction(ctx context.Context) (store.Transaction, error) {
	args := s.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(store.Transaction), args.Error(1)
}

func TestRegistry_InitAndGetAdapter(t *testing.T) {
	mockStore := NewMockStoreForSecrets()
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	realSm, err := secrets.NewSecretManager(mockStore, hexKey, "local", nil)
	require.NoError(t, err)
	registry := NewRegistry(realSm)

	secretID1, err := realSm.CreateSecret(context.Background(), "p1_secret_name", "api_key", "p1_secret_value", "p1")
	require.NoError(t, err)
	secretID2, err := realSm.CreateSecret(context.Background(), "p2_secret_name", "api_key", "p2_secret_value", "p2")
	require.NoError(t, err)

	providerCfgs := []config.ProviderConfig{
		{ID: "p1", Name: "test-llm", Type: config.ProviderTypeLLM, Status: "active", CredentialsSecretID: secretID1, LLMConfig: &config.LLMProviderConfig{}},
		{ID: "p2", Name: "test-tool", Type: config.ProviderTypeToolServer, Status: "active", CredentialsSecretID: secretID2, MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "http://localhost"}},
	}

	registry.InitAdapters(providerCfgs)

	retrievedLLM, err := registry.GetAdapter("p1")
	require.NoError(t, err)
	require.NotNil(t, retrievedLLM)
	assert.Equal(t, "test-llm", retrievedLLM.ProviderInfo().Name)
	assert.Implements(t, (*ProviderAdapter)(nil), retrievedLLM)

	retrievedTool, err := registry.GetAdapter("p2")
	require.NoError(t, err)
	require.NotNil(t, retrievedTool)
	assert.Equal(t, "test-tool", retrievedTool.ProviderInfo().Name)
	assert.Implements(t, (*ProviderAdapter)(nil), retrievedTool)

	_, err = registry.GetAdapter("non-existent")
	assert.Error(t, err)
}

func TestRegistry_InitAdapters(t *testing.T) {
	mockStore := NewMockStoreForSecrets()
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	realSm, err := secrets.NewSecretManager(mockStore, hexKey, "local", nil)
	require.NoError(t, err)
	registry := NewRegistry(realSm)

	t.Run("SuccessfulInit_OpenAI", func(t *testing.T) {
		registry.adapters = make(map[string]ProviderAdapter)
		secretID, err := realSm.CreateSecret(context.Background(), "openai_secret_name", "api_key", "openai-key-value", "p-good-openai")
		require.NoError(t, err)

		providerCfgs := []config.ProviderConfig{
			{ID: "p-good-openai", Name: "openai-good", Type: config.ProviderTypeLLM, Status: "active", CredentialsSecretID: secretID, LLMConfig: &config.LLMProviderConfig{}},
		}
		registry.InitAdapters(providerCfgs)
		adapter, err := registry.GetAdapter("p-good-openai")
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "openai-good", adapter.ProviderInfo().Name)
	})

	t.Run("SuccessfulInit_Anthropic", func(t *testing.T) {
		registry.adapters = make(map[string]ProviderAdapter)
		secretIDAnthropic, err := realSm.CreateSecret(context.Background(), "anthropic_secret_name", "api_key", "anthropic-key-value", "p-good-anthropic")
		require.NoError(t, err)
		providerCfgs := []config.ProviderConfig{
			{ID: "p-good-anthropic", Name: "anthropic-good", Type: config.ProviderTypeLLM, Status: "active", CredentialsSecretID: secretIDAnthropic, LLMConfig: &config.LLMProviderConfig{APIBase: "dummy-anthropic"}},
		}
		registry.InitAdapters(providerCfgs)
		adapter, err := registry.GetAdapter("p-good-anthropic")
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "anthropic-good", adapter.ProviderInfo().Name)
		assert.Equal(t, config.ProviderTypeLLM, adapter.ProviderInfo().Type)
	})

	t.Run("SuccessfulInit_VertexAI", func(t *testing.T) {
		registry.adapters = make(map[string]ProviderAdapter)
		secretIDVertex, err := realSm.CreateSecret(context.Background(), "vertex_secret_name", "api_key", "vertex-key-value", "p-good-vertex")
		require.NoError(t, err)
		providerCfgs := []config.ProviderConfig{
			{ID: "p-good-vertex", Name: "vertexai-good", Type: config.ProviderTypeLLM, Status: "active", CredentialsSecretID: secretIDVertex, LLMConfig: &config.LLMProviderConfig{APIBase: "dummy-vertex"}},
		}
		registry.InitAdapters(providerCfgs)
		adapter, err := registry.GetAdapter("p-good-vertex")
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "vertexai-good", adapter.ProviderInfo().Name)
		assert.Equal(t, config.ProviderTypeLLM, adapter.ProviderInfo().Type)
	})

	t.Run("SuccessfulInit_A2APlatform", func(t *testing.T) {
		registry.adapters = make(map[string]ProviderAdapter)
		secretIDA2A, err := realSm.CreateSecret(context.Background(), "a2a_secret_name", "api_key", "a2a-key-value", "p-good-a2a")
		require.NoError(t, err)
		providerCfgs := []config.ProviderConfig{
			{ID: "p-good-a2a", Name: "a2a-good", Type: config.ProviderTypeAgentPlatform, Status: "active", CredentialsSecretID: secretIDA2A, A2APlatformConfig: &config.A2APlatformConfig{HubAddress: "http://localhost:1234"}},
		}
		registry.InitAdapters(providerCfgs)
		adapter, err := registry.GetAdapter("p-good-a2a")
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "a2a-good", adapter.ProviderInfo().Name)
		assert.Equal(t, config.ProviderTypeAgentPlatform, adapter.ProviderInfo().Type)
	})

	t.Run("InactiveProvider", func(t *testing.T) {
		registry.adapters = make(map[string]ProviderAdapter)
		providerCfgs := []config.ProviderConfig{
			{ID: "p-inactive", Name: "llm-inactive", Type: config.ProviderTypeLLM, Status: "disabled", CredentialsSecretID: "valid-secret", LLMConfig: &config.LLMProviderConfig{}},
		}
		registry.InitAdapters(providerCfgs)
		_, errGet := registry.GetAdapter("p-inactive")
		assert.Error(t, errGet, "Adapter for inactive provider should not be found")
	})

	t.Run("NoFactoryForUnknownType", func(t *testing.T) {
		registry.adapters = make(map[string]ProviderAdapter)
		providerCfgs := []config.ProviderConfig{
			{ID: "p-unknown", Name: "unknown-type-provider", Type: "some_unknown_type", Status: "active"},
		}
		registry.InitAdapters(providerCfgs)
		_, errGet := registry.GetAdapter("p-unknown")
		assert.Error(t, errGet, "Adapter for unknown type should not be found")
	})

	t.Run("AdapterInitFailure_SecretMissing", func(t *testing.T) {
		registry.adapters = make(map[string]ProviderAdapter)
		providerCfgs := []config.ProviderConfig{
			{ID: "p-fail-secret", Name: "llm-fail-secret", Type: config.ProviderTypeLLM, Status: "active", CredentialsSecretID: "missing-secret", LLMConfig: &config.LLMProviderConfig{}},
		}
		registry.InitAdapters(providerCfgs)
		_, errGet := registry.GetAdapter("p-fail-secret")
		assert.Error(t, errGet, "Adapter that failed to init due to missing secret should not be available")
	})
}

func TestRegistry_Shutdown(t *testing.T) {
	mockStore := NewMockStoreForSecrets()
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	realSm, err := secrets.NewSecretManager(mockStore, hexKey, "local", nil)
	require.NoError(t, err)
	registry := NewRegistry(realSm)

	mockAdapterInstance := &MockLLMAdapter{name: "llm-for-shutdown"}
	mockAdapterInstance.On("Shutdown").Return(nil)

	registry.mu.Lock()
	registry.adapters["p-shutdown"] = mockAdapterInstance
	registry.mu.Unlock()

	registry.Shutdown()
	mockAdapterInstance.AssertCalled(t, "Shutdown")
	assert.Empty(t, registry.adapters, "Adapters map should be cleared after shutdown")
}
