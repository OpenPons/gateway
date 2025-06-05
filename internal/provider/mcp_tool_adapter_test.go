package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	// "net/http/httptest" // Will be needed for InvokeTool, HealthCheck tests

	"github.com/openpons/gateway/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretRetriever is defined in provider_test_helpers.go

func TestNewMCPToolAdapter(t *testing.T) {
	mockSR := &mockSecretRetriever{secrets: make(map[string]string)}
	mockSR.secrets["mcp-secret-id"] = "test-mcp-api-key"

	t.Run("Successful creation with HTTP address", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "pmcp1",
			Name:                "mcp-http-test",
			Type:                config.ProviderTypeToolServer,
			CredentialsSecretID: "mcp-secret-id",
			MCPToolConfig:       &config.MCPToolServerConfig{ServerAddress: "http://localhost:8080"},
		}
		adapter, err := NewMCPToolAdapter(cfg, mockSR, nil)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "test-mcp-api-key", adapter.apiKey)
		assert.Equal(t, "mcp-http-test", adapter.name)
		assert.Equal(t, "http", adapter.serverScheme)
		assert.Equal(t, "http://localhost:8080", adapter.serverAddrParsed)
		assert.NotNil(t, adapter.httpClient) // Default client should be created
	})

	t.Run("Successful creation with HTTPS address", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:            "pmcp-https",
			Name:          "mcp-https-test",
			Type:          config.ProviderTypeToolServer,
			MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "https://secure.example.com"},
		}
		adapter, err := NewMCPToolAdapter(cfg, mockSR, nil)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "https", adapter.serverScheme)
		assert.Equal(t, "https://secure.example.com", adapter.serverAddrParsed)
	})

	t.Run("Successful creation with gRPC address", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:            "pmcp-grpc",
			Name:          "mcp-grpc-test",
			Type:          config.ProviderTypeToolServer,
			MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "grpc://localhost:9090"},
		}
		adapter, err := NewMCPToolAdapter(cfg, mockSR, nil)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "grpc", adapter.serverScheme)
		assert.Equal(t, "localhost:9090", adapter.serverAddrParsed)
		assert.Nil(t, adapter.httpClient) // HTTP client not created for grpc
	})

	t.Run("Successful creation with stdio address", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:            "pmcp-stdio",
			Name:          "mcp-stdio-test",
			Type:          config.ProviderTypeToolServer,
			MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "stdio:/path/to/command"},
		}
		adapter, err := NewMCPToolAdapter(cfg, mockSR, nil)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "stdio", adapter.serverScheme)
		assert.Equal(t, "/path/to/command", adapter.serverAddrParsed)
		assert.Nil(t, adapter.httpClient)
	})

	t.Run("Address without scheme defaults to http", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:            "pmcp-no-scheme",
			Name:          "mcp-no-scheme-test",
			Type:          config.ProviderTypeToolServer,
			MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "localhost:8080"},
		}
		adapter, err := NewMCPToolAdapter(cfg, mockSR, nil)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "http", adapter.serverScheme)
		assert.Equal(t, "http://localhost:8080", adapter.serverAddrParsed)
	})

	t.Run("Missing MCPToolConfig", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:   "pmcp2",
			Name: "mcp-no-config",
			Type: config.ProviderTypeToolServer,
		}
		_, err := NewMCPToolAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MCPToolAdapter requires MCPToolConfig to be set")
	})

	t.Run("Secret retrieval error", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "pmcp3",
			Name:                "mcp-secret-error",
			Type:                config.ProviderTypeToolServer,
			CredentialsSecretID: "nonexistent-mcp-secret",
			MCPToolConfig:       &config.MCPToolServerConfig{ServerAddress: "http://localhost:8080"},
		}
		_, err := NewMCPToolAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve API key for MCP provider")
	})

	t.Run("Custom HTTP client provided", func(t *testing.T) {
		customClient := &http.Client{}
		cfg := config.ProviderConfig{
			ID:            "pmcp-custom-http",
			Name:          "mcp-custom-http-test",
			Type:          config.ProviderTypeToolServer,
			MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "http://custom.example.com"},
		}
		adapter, err := NewMCPToolAdapter(cfg, mockSR, customClient)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Same(t, customClient, adapter.httpClient)
	})
}

func TestMCPToolAdapter_Init(t *testing.T) {
	mockSR := &mockSecretRetriever{secrets: make(map[string]string)}
	mockSR.secrets["mcp-init-secret"] = "init-mcp-key"

	baseCfg := config.ProviderConfig{
		ID:            "pmcp-init",
		Name:          "mcp-init-base",
		Type:          config.ProviderTypeToolServer,
		MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "http://localhost:7070"},
	}
	adapter, err := NewMCPToolAdapter(baseCfg, mockSR, nil)
	require.NoError(t, err)
	require.Equal(t, "", adapter.apiKey) // No secret ID in baseCfg

	t.Run("Successful Init with new secret and address", func(t *testing.T) {
		newCfg := baseCfg
		newCfg.CredentialsSecretID = "mcp-init-secret"
		newCfg.MCPToolConfig.ServerAddress = "https://newserver.com/mcp"
		err := adapter.Init(&newCfg, mockSR)
		require.NoError(t, err)
		assert.Equal(t, "init-mcp-key", adapter.apiKey)
		assert.Equal(t, "https", adapter.serverScheme)
		assert.Equal(t, "https://newserver.com/mcp", adapter.serverAddrParsed)
	})

	t.Run("Init with missing MCPToolConfig", func(t *testing.T) {
		cfgNoMCP := config.ProviderConfig{ID: "pmcp-init-no-mcp", Name: "No MCP Config", Type: config.ProviderTypeToolServer}
		err := adapter.Init(&cfgNoMCP, mockSR)
		require.NoError(t, err) // Init currently defaults MCPToolConfig if nil, might be desired or not
		assert.NotNil(t, adapter.cfg.MCPToolConfig, "MCPToolConfig should be initialized by Init if nil")
		assert.Equal(t, "http", adapter.serverScheme, "Default scheme should be http if address is empty")
	})
}

// Helper to setup a test server and an MCPToolAdapter pointing to it
func setupMCPToolAdapterTest(t *testing.T, handler http.HandlerFunc, serverAddress string) (*MCPToolAdapter, *httptest.Server, func()) {
	server := httptest.NewServer(handler)

	// Determine actual server URL to use in config, replacing placeholder in serverAddress if needed
	finalServerAddress := serverAddress
	if strings.Contains(serverAddress, "PLACEHOLDER_SERVER_URL") {
		finalServerAddress = strings.Replace(serverAddress, "PLACEHOLDER_SERVER_URL", server.URL, 1)
	}

	mockSR := &mockSecretRetriever{secrets: map[string]string{"test-key-mcp": "fake-mcp-api-key"}}
	cfg := config.ProviderConfig{
		ID:                  "test-mcp-provider",
		Name:                "TestMCPTool",
		Type:                config.ProviderTypeToolServer,
		CredentialsSecretID: "test-key-mcp",
		MCPToolConfig:       &config.MCPToolServerConfig{ServerAddress: finalServerAddress},
	}

	// Use server.Client() for the adapter so it talks to the mock server
	adapter, err := NewMCPToolAdapter(cfg, mockSR, server.Client())
	require.NoError(t, err)
	require.NotNil(t, adapter)

	cleanup := func() {
		server.Close()
	}
	return adapter, server, cleanup
}

func TestMCPToolAdapter_InvokeTool(t *testing.T) {
	toolName := "test_tool"
	args := map[string]interface{}{"param1": "value1"}

	t.Run("Successful InvokeTool", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, fmt.Sprintf("/invoke/%s", toolName), r.URL.Path)
			assert.Equal(t, "Bearer fake-mcp-api-key", r.Header.Get("Authorization"))

			var reqArgs map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&reqArgs)
			require.NoError(t, err)
			assert.Equal(t, args, reqArgs)

			resp := ToolInvocationResponse{Result: map[string]string{"output": "success"}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
		adapter, _, cleanup := setupMCPToolAdapterTest(t, handler, "PLACEHOLDER_SERVER_URL") // URL will be replaced by mock server's
		defer cleanup()

		resp, err := adapter.InvokeTool(context.Background(), &ToolInvocationRequest{ToolName: toolName, Arguments: args})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, map[string]interface{}{"output": "success"}, resp.Result)
	})

	t.Run("InvokeTool with server error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error": {"type": "server_error", "message": "MCP server down"}}`)
		}
		adapter, _, cleanup := setupMCPToolAdapterTest(t, handler, "PLACEHOLDER_SERVER_URL")
		defer cleanup()

		_, err := adapter.InvokeTool(context.Background(), &ToolInvocationRequest{ToolName: toolName, Arguments: args})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MCP server request for tool test_tool failed with status 500")
	})

	t.Run("InvokeTool with unsupported scheme (grpc)", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID: "mcp-grpc-inv", Name: "MCP GRPC Invoke", Type: config.ProviderTypeToolServer,
			MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "grpc://localhost:9000"},
		}
		adapter, _ := NewMCPToolAdapter(cfg, &mockSecretRetriever{}, nil)
		_, err := adapter.InvokeTool(context.Background(), &ToolInvocationRequest{ToolName: "grpc_tool"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not support InvokeTool with scheme 'grpc'")
	})
}

func TestMCPToolAdapter_HealthCheck(t *testing.T) {
	t.Run("Successful HealthCheck", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/healthz", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}
		adapter, _, cleanup := setupMCPToolAdapterTest(t, handler, "PLACEHOLDER_SERVER_URL")
		defer cleanup()
		err := adapter.HealthCheck(context.Background())
		require.NoError(t, err)
	})

	t.Run("Failed HealthCheck", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		adapter, _, cleanup := setupMCPToolAdapterTest(t, handler, "PLACEHOLDER_SERVER_URL")
		defer cleanup()
		err := adapter.HealthCheck(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MCP server TestMCPTool health check failed with status 503")
	})

	t.Run("HealthCheck skipped for non-http/s scheme", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID: "mcp-grpc-hc", Name: "MCP GRPC HC", Type: config.ProviderTypeToolServer,
			MCPToolConfig: &config.MCPToolServerConfig{ServerAddress: "grpc://localhost:9000"},
		}
		adapter, _ := NewMCPToolAdapter(cfg, &mockSecretRetriever{}, nil)
		err := adapter.HealthCheck(context.Background())
		require.NoError(t, err, "HealthCheck for grpc should be skipped and return no error")
	})
}

func TestMCPToolAdapter_NotImplementedMethods(t *testing.T) {
	adapter, _, cleanup := setupMCPToolAdapterTest(t, nil, "http://dummy.com") // Address needed for client init
	defer cleanup()

	t.Run("ChatCompletion", func(t *testing.T) {
		_, err := adapter.ChatCompletion(context.Background(), &ChatCompletionRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported by MCPToolAdapter")
	})
	t.Run("StreamChatCompletion", func(t *testing.T) {
		err := adapter.StreamChatCompletion(context.Background(), &ChatCompletionRequest{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported by MCPToolAdapter")
	})
	t.Run("GenerateEmbedding", func(t *testing.T) {
		_, err := adapter.GenerateEmbedding(context.Background(), &EmbeddingRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported by MCPToolAdapter")
	})
	t.Run("AudioTranscription", func(t *testing.T) {
		_, err := adapter.AudioTranscription(context.Background(), &AudioTranscriptionRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported by MCPToolAdapter")
	})
	t.Run("TextToSpeech", func(t *testing.T) {
		err := adapter.TextToSpeech(context.Background(), &TextToSpeechRequest{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported by MCPToolAdapter")
	})
	t.Run("StreamInvokeTool", func(t *testing.T) {
		err := adapter.StreamInvokeTool(context.Background(), nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requestStream and responseStream cannot be nil")
	})
}
