package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	// "net/http/httptest" // Will be needed for InvokeTool, HealthCheck tests

	"github.com/openpons/gateway/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretRetriever is defined in provider_test_helpers.go

func TestNewA2APlatformAdapter(t *testing.T) {
	mockSR := &mockSecretRetriever{secrets: make(map[string]string)}
	mockSR.secrets["a2a-secret-id"] = "test-a2a-api-key"

	t.Run("Successful creation", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "pa2a1",
			Name:                "a2a-test",
			Type:                config.ProviderTypeAgentPlatform,
			CredentialsSecretID: "a2a-secret-id",
			A2APlatformConfig:   &config.A2APlatformConfig{HubAddress: "http://localhost:8081/a2a"},
		}
		adapter, err := NewA2APlatformAdapter(cfg, mockSR, nil)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "test-a2a-api-key", adapter.apiKey)
		assert.Equal(t, "a2a-test", adapter.name)
		assert.NotNil(t, adapter.httpClient) // Default client should be created
	})

	t.Run("Missing A2APlatformConfig", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:   "pa2a2",
			Name: "a2a-no-config",
			Type: config.ProviderTypeAgentPlatform,
		}
		_, err := NewA2APlatformAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "A2APlatformAdapter requires A2APlatformConfig to be set")
	})

	t.Run("Secret retrieval error", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "pa2a3",
			Name:                "a2a-secret-error",
			Type:                config.ProviderTypeAgentPlatform,
			CredentialsSecretID: "nonexistent-a2a-secret",
			A2APlatformConfig:   &config.A2APlatformConfig{HubAddress: "http://localhost:8081"},
		}
		_, err := NewA2APlatformAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve API key for A2A provider")
	})

	t.Run("No secret ID provided", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                "pa2a4",
			Name:              "a2a-no-secret",
			Type:              config.ProviderTypeAgentPlatform,
			A2APlatformConfig: &config.A2APlatformConfig{HubAddress: "http://localhost:8081"},
		}
		adapter, err := NewA2APlatformAdapter(cfg, mockSR, nil)
		require.NoError(t, err) // Should log info, not error
		require.NotNil(t, adapter)
		assert.Equal(t, "", adapter.apiKey)
	})

	t.Run("Custom HTTP client provided", func(t *testing.T) {
		customClient := &http.Client{}
		cfg := config.ProviderConfig{
			ID:                "pa2a5",
			Name:              "a2a-custom-http",
			Type:              config.ProviderTypeAgentPlatform,
			A2APlatformConfig: &config.A2APlatformConfig{HubAddress: "http://custom.a2a.com"},
		}
		adapter, err := NewA2APlatformAdapter(cfg, mockSR, customClient)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Same(t, customClient, adapter.httpClient)
	})
}

func TestA2APlatformAdapter_Init(t *testing.T) {
	mockSR := &mockSecretRetriever{secrets: make(map[string]string)}
	mockSR.secrets["a2a-init-secret"] = "init-a2a-key"

	baseCfg := config.ProviderConfig{
		ID:                "pa2a-init",
		Name:              "a2a-init-base",
		Type:              config.ProviderTypeAgentPlatform,
		A2APlatformConfig: &config.A2APlatformConfig{HubAddress: "http://localhost:7071"},
	}
	adapter, err := NewA2APlatformAdapter(baseCfg, mockSR, nil)
	require.NoError(t, err)
	require.Equal(t, "", adapter.apiKey) // No secret ID in baseCfg

	t.Run("Successful Init with new secret and address", func(t *testing.T) {
		newCfg := baseCfg
		newCfg.CredentialsSecretID = "a2a-init-secret"
		newCfg.A2APlatformConfig.HubAddress = "https://new.a2ahub.com"
		err := adapter.Init(&newCfg, mockSR)
		require.NoError(t, err)
		assert.Equal(t, "init-a2a-key", adapter.apiKey)
		assert.Equal(t, "https://new.a2ahub.com", adapter.cfg.A2APlatformConfig.HubAddress)
	})

	t.Run("Init with missing A2APlatformConfig", func(t *testing.T) {
		cfgNoA2A := config.ProviderConfig{ID: "pa2a-init-no-cfg", Name: "No A2A Config", Type: config.ProviderTypeAgentPlatform}
		err := adapter.Init(&cfgNoA2A, mockSR)
		require.NoError(t, err) // Init defaults A2APlatformConfig
		assert.NotNil(t, adapter.cfg.A2APlatformConfig)
		assert.Equal(t, "", adapter.cfg.A2APlatformConfig.HubAddress) // Defaulted HubAddress is empty
	})
}

// Helper to setup a test server and an A2APlatformAdapter pointing to it
func setupA2APlatformAdapterTest(t *testing.T, handler http.HandlerFunc) (*A2APlatformAdapter, *httptest.Server, func()) {
	server := httptest.NewServer(handler)

	mockSR := &mockSecretRetriever{secrets: map[string]string{"test-key-a2a": "fake-a2a-api-key"}}
	cfg := config.ProviderConfig{
		ID:                  "test-a2a-provider",
		Name:                "TestA2APlatform",
		Type:                config.ProviderTypeAgentPlatform,
		CredentialsSecretID: "test-key-a2a",
		A2APlatformConfig:   &config.A2APlatformConfig{HubAddress: server.URL},
	}

	adapter, err := NewA2APlatformAdapter(cfg, mockSR, server.Client())
	require.NoError(t, err)
	require.NotNil(t, adapter)

	cleanup := func() {
		server.Close()
	}
	return adapter, server, cleanup
}

func TestA2APlatformAdapter_InvokeTool(t *testing.T) {
	taskName := "test_task"
	args := map[string]interface{}{"input_data": "sample"}

	t.Run("Successful InvokeTool", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, fmt.Sprintf("/invoke/%s", taskName), r.URL.Path)
			assert.Equal(t, "Bearer fake-a2a-api-key", r.Header.Get("Authorization"))

			var reqArgs map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&reqArgs)
			require.NoError(t, err)
			assert.Equal(t, args, reqArgs)

			resp := ToolInvocationResponse{Result: map[string]string{"status": "completed"}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
		adapter, _, cleanup := setupA2APlatformAdapterTest(t, handler)
		defer cleanup()

		resp, err := adapter.InvokeTool(context.Background(), &ToolInvocationRequest{ToolName: taskName, Arguments: args})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, map[string]interface{}{"status": "completed"}, resp.Result)
	})

	t.Run("InvokeTool with HubAddress not configured", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID: "a2a-no-hub", Name: "No Hub Address", Type: config.ProviderTypeAgentPlatform,
			A2APlatformConfig: &config.A2APlatformConfig{HubAddress: ""}, // Empty HubAddress
		}
		adapter, _ := NewA2APlatformAdapter(cfg, &mockSecretRetriever{}, nil)
		_, err := adapter.InvokeTool(context.Background(), &ToolInvocationRequest{ToolName: taskName})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "A2A HubAddress is not configured")
	})
}

func TestA2APlatformAdapter_HealthCheck(t *testing.T) {
	t.Run("Successful HealthCheck", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/healthz", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}
		adapter, _, cleanup := setupA2APlatformAdapterTest(t, handler)
		defer cleanup()
		err := adapter.HealthCheck(context.Background())
		require.NoError(t, err)
	})

	t.Run("HealthCheck with HubAddress not configured", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID: "a2a-hc-no-hub", Name: "HC No Hub", Type: config.ProviderTypeAgentPlatform,
			A2APlatformConfig: &config.A2APlatformConfig{HubAddress: ""},
		}
		adapter, _ := NewA2APlatformAdapter(cfg, &mockSecretRetriever{}, nil)
		err := adapter.HealthCheck(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HubAddress not configured for A2A provider")
	})
}

func TestA2APlatformAdapter_NotImplementedMethods(t *testing.T) {
	adapter, _, cleanup := setupA2APlatformAdapterTest(t, nil) // HTTP client needed for some internal defaults
	defer cleanup()

	// LLM methods
	_, err := adapter.ChatCompletion(context.Background(), &ChatCompletionRequest{})
	assert.ErrorContains(t, err, "not supported by A2APlatformAdapter")
	err = adapter.StreamChatCompletion(context.Background(), &ChatCompletionRequest{}, nil)
	assert.ErrorContains(t, err, "not supported by A2APlatformAdapter")
	_, err = adapter.GenerateEmbedding(context.Background(), &EmbeddingRequest{})
	assert.ErrorContains(t, err, "not supported by A2APlatformAdapter")
	_, err = adapter.AudioTranscription(context.Background(), &AudioTranscriptionRequest{})
	assert.ErrorContains(t, err, "not supported by A2APlatformAdapter")
	err = adapter.TextToSpeech(context.Background(), &TextToSpeechRequest{}, nil)
	assert.ErrorContains(t, err, "not supported by A2APlatformAdapter")

	// StreamInvokeTool
	err = adapter.StreamInvokeTool(context.Background(), nil, nil)
	assert.ErrorContains(t, err, "not yet implemented")
}
