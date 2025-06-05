package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openpons/gateway/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretRetriever is defined in provider_test_helpers.go

func TestNewAnthropicAdapter(t *testing.T) {
	mockSR := &mockSecretRetriever{secrets: make(map[string]string)} // Assuming mockSecretRetriever is available
	mockSR.secrets["anthropic-secret-id"] = "test-anthropic-api-key"

	t.Run("Successful creation", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "pa1",
			Name:                "anthropic-test",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "anthropic-secret-id",
			LLMConfig:           &config.LLMProviderConfig{APIBase: "https://api.anthropic.com/v1"},
		}
		adapter, err := NewAnthropicAdapter(cfg, mockSR, nil)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "test-anthropic-api-key", adapter.apiKey)
		assert.Equal(t, "anthropic-test", adapter.name)
	})

	t.Run("Missing LLMConfig", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "pa2",
			Name:                "anthropic-no-llm-config",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "anthropic-secret-id",
		}
		_, err := NewAnthropicAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "anthropic adapter requires LLMConfig to be set")
	})

	t.Run("Secret retrieval error", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "pa3",
			Name:                "anthropic-secret-error",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "nonexistent-anthropic-secret",
			LLMConfig:           &config.LLMProviderConfig{},
		}
		_, err := NewAnthropicAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve API key for Anthropic provider")
	})

	t.Run("Empty API key", func(t *testing.T) {
		mockSR.secrets["empty-anthropic-secret"] = ""
		cfg := config.ProviderConfig{
			ID:                  "pa4",
			Name:                "anthropic-empty-key",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "empty-anthropic-secret",
			LLMConfig:           &config.LLMProviderConfig{},
		}
		_, err := NewAnthropicAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "retrieved API key for Anthropic provider")
		assert.Contains(t, err.Error(), "is empty")
		delete(mockSR.secrets, "empty-anthropic-secret") // cleanup
	})

	t.Run("No secret ID provided", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:        "pa5",
			Name:      "anthropic-no-secret-id",
			Type:      config.ProviderTypeLLM,
			LLMConfig: &config.LLMProviderConfig{},
		}
		adapter, err := NewAnthropicAdapter(cfg, mockSR, nil)
		require.NoError(t, err) // Should log warning, not error
		require.NotNil(t, adapter)
		assert.Equal(t, "", adapter.apiKey)
	})
}

// Helper to setup a test server and an AnthropicAdapter pointing to it
func setupAnthropicAdapterTest(t *testing.T, handler http.HandlerFunc) (*AnthropicAdapter, *httptest.Server, func()) {
	server := httptest.NewServer(handler)

	mockSR := &mockSecretRetriever{secrets: map[string]string{"test-key-anthropic": "fake-anthropic-api-key"}}
	cfg := config.ProviderConfig{
		ID:                  "test-anthropic-provider",
		Name:                "TestAnthropic",
		Type:                config.ProviderTypeLLM,
		CredentialsSecretID: "test-key-anthropic",
		LLMConfig:           &config.LLMProviderConfig{APIBase: server.URL}, // Point to mock server
	}

	adapter, err := NewAnthropicAdapter(cfg, mockSR, server.Client())
	require.NoError(t, err)
	require.NotNil(t, adapter)

	cleanup := func() {
		server.Close()
	}
	return adapter, server, cleanup
}

func TestAnthropicAdapter_Init(t *testing.T) {
	mockSR := &mockSecretRetriever{secrets: make(map[string]string)}
	mockSR.secrets["anthropic-init-secret"] = "init-key-anthropic"

	baseCfg := config.ProviderConfig{
		ID:        "pa-init",
		Name:      "anthropic-init-test",
		Type:      config.ProviderTypeLLM,
		LLMConfig: &config.LLMProviderConfig{APIBase: "https://api.anthropic.com/v1"},
	}
	adapter, err := NewAnthropicAdapter(baseCfg, mockSR, nil)
	require.NoError(t, err)
	require.Equal(t, "", adapter.apiKey) // No secret ID in baseCfg

	t.Run("Successful Init with new secret", func(t *testing.T) {
		newCfg := baseCfg
		newCfg.CredentialsSecretID = "anthropic-init-secret"
		err := adapter.Init(&newCfg, mockSR)
		require.NoError(t, err)
		assert.Equal(t, "init-key-anthropic", adapter.apiKey)
		assert.Equal(t, newCfg.ID, adapter.id)
	})

	t.Run("Init with missing secret", func(t *testing.T) {
		failCfg := baseCfg
		failCfg.CredentialsSecretID = "missing-anthropic-init-secret"
		err := adapter.Init(&failCfg, mockSR)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve API key for Anthropic provider")
	})

	t.Run("Init with nil config", func(t *testing.T) {
		err := adapter.Init(nil, mockSR)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "provider config cannot be nil")
	})

	t.Run("Init with nil secret retriever", func(t *testing.T) {
		err := adapter.Init(&baseCfg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret retriever cannot be nil")
	})
}

func TestAnthropicAdapter_ChatCompletion(t *testing.T) {
	t.Run("Successful chat completion", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/messages", r.URL.Path)
			assert.Equal(t, "fake-anthropic-api-key", r.Header.Get("x-api-key"))
			assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))

			var reqBody AnthropicChatRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "claude-2", reqBody.Model)
			require.Len(t, reqBody.Messages, 1)
			assert.Equal(t, "user", reqBody.Messages[0].Role)
			require.Len(t, reqBody.Messages[0].Content, 1)
			contentBlock := reqBody.Messages[0].Content[0].(map[string]interface{})
			assert.Equal(t, "text", contentBlock["type"])
			assert.Equal(t, "Hello Anthropic", contentBlock["text"])
			assert.Equal(t, "Test System Prompt", reqBody.System)

			resp := AnthropicChatResponse{
				ID:   "msg_123",
				Type: "message",
				Role: "assistant",
				Content: []AnthropicChatResponseContent{
					{Type: "text", Text: "Hello from Anthropic!"},
				},
				Model:      "claude-2",
				StopReason: "end_turn",
				Usage: struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				}{InputTokens: 20, OutputTokens: 15},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
		adapter, _, cleanup := setupAnthropicAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{
			Model: "claude-2",
			Messages: []ChatMessage{
				{Role: "system", Content: "Test System Prompt"},
				{Role: "user", Content: "Hello Anthropic"},
			},
			MaxTokens: 100,
		}
		resp, err := adapter.ChatCompletion(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "msg_123", resp.ID)
		require.Len(t, resp.Choices, 1)
		assert.Equal(t, "assistant", resp.Choices[0].Message.Role)
		assert.Equal(t, "Hello from Anthropic!", resp.Choices[0].Message.Content)
		assert.Equal(t, "stop", resp.Choices[0].FinishReason)
		require.NotNil(t, resp.Usage)
		assert.Equal(t, 20, resp.Usage.PromptTokens)
		assert.Equal(t, 15, resp.Usage.CompletionTokens)
		assert.Equal(t, 35, resp.Usage.TotalTokens)
	})

	t.Run("Successful chat completion with tool calls", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			var reqBody AnthropicChatRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "claude-2-tools", reqBody.Model)
			require.Len(t, reqBody.Tools, 1)
			assert.Equal(t, "get_current_weather", reqBody.Tools[0].Name)
			assert.JSONEq(t, `{"type":"object","properties":{"location":{"type":"string","description":"The city and state, e.g. San Francisco, CA"},"unit":{"type":"string","enum":["celsius","fahrenheit"]}},"required":["location"]}`, string(reqBody.Tools[0].InputSchema))

			resp := AnthropicChatResponse{
				ID:   "msg_tools_123",
				Type: "message",
				Role: "assistant",
				Content: []AnthropicChatResponseContent{
					{
						Type: "tool_use",
						ID:   "tool_call_abc",
						Name: "get_current_weather",
						Input: map[string]interface{}{
							"location": "San Francisco, CA",
							"unit":     "fahrenheit",
						},
					},
				},
				Model:      "claude-2-tools",
				StopReason: "tool_use",
				Usage: struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				}{InputTokens: 50, OutputTokens: 20},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
		adapter, _, cleanup := setupAnthropicAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{
			Model: "claude-2-tools",
			Messages: []ChatMessage{
				{Role: "user", Content: "What's the weather in San Francisco?"},
			},
			Tools: []Tool{
				{
					Type: "function",
					Function: FunctionDefinition{
						Name:        "get_current_weather",
						Description: "Get the current weather in a given location",
						Parameters:  json.RawMessage(`{"type":"object","properties":{"location":{"type":"string","description":"The city and state, e.g. San Francisco, CA"},"unit":{"type":"string","enum":["celsius","fahrenheit"]}},"required":["location"]}`),
					},
				},
			},
		}

		resp, err := adapter.ChatCompletion(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "msg_tools_123", resp.ID)
		require.Len(t, resp.Choices, 1)
		choice := resp.Choices[0]
		assert.Equal(t, "assistant", choice.Message.Role)
		assert.Empty(t, choice.Message.Content, "Content should be empty when tool_calls are present")
		require.Len(t, choice.Message.ToolCalls, 1)
		toolCall := choice.Message.ToolCalls[0]
		assert.Equal(t, "tool_call_abc", toolCall.ID)
		assert.Equal(t, "function", toolCall.Type)
		assert.Equal(t, "get_current_weather", toolCall.Function.Name)
		assert.JSONEq(t, `{"location":"San Francisco, CA", "unit":"fahrenheit"}`, toolCall.Function.Arguments)
		assert.Equal(t, "tool_calls", choice.FinishReason)
		require.NotNil(t, resp.Usage)
		assert.Equal(t, 70, resp.Usage.TotalTokens)
	})

	t.Run("API error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			errorResp := map[string]interface{}{
				"type": "error",
				"error": map[string]string{
					"type":    "authentication_error",
					"message": "Invalid API Key",
				},
			}
			json.NewEncoder(w).Encode(errorResp)
		}
		adapter, _, cleanup := setupAnthropicAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{Model: "claude-2", Messages: []ChatMessage{{Role: "user", Content: "Hi"}}}
		_, err := adapter.ChatCompletion(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Anthropic API request failed with status 403")
		assert.Contains(t, err.Error(), "Invalid API Key")
	})
}

func TestAnthropicAdapter_StreamChatCompletion(t *testing.T) {
	t.Run("Successful stream chat completion", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/messages", r.URL.Path)
			assert.Equal(t, "fake-anthropic-api-key", r.Header.Get("x-api-key"))

			var reqBody AnthropicChatRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.True(t, reqBody.Stream, "Stream field should be true")

			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_stream_123\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-2\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":25}}}\n\n")
			fmt.Fprintf(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
			fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n")
			fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n")
			fmt.Fprintf(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
			fmt.Fprintf(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n")
			fmt.Fprintf(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		}
		adapter, _, cleanup := setupAnthropicAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{
			Model:     "claude-2",
			Messages:  []ChatMessage{{Role: "user", Content: "Hi"}},
			Stream:    true,
			MaxTokens: 10,
		}
		var streamOutput bytes.Buffer
		err := adapter.StreamChatCompletion(context.Background(), req, &streamOutput)
		require.NoError(t, err)

		outputStr := streamOutput.String()
		assert.Contains(t, outputStr, `"id":"msg_stream_123"`)
		assert.Contains(t, outputStr, `"delta":{"role":"assistant"`)
		assert.Contains(t, outputStr, `"delta":{"role":"","content":"Hello"}`)
		assert.Contains(t, outputStr, `"delta":{"role":"","content":" world"}`)
		assert.Contains(t, outputStr, `"finish_reason":"stop"`)
		assert.Contains(t, outputStr, `"prompt_tokens":25`)
		assert.Contains(t, outputStr, `"completion_tokens":5`)
		assert.Contains(t, outputStr, "data: [DONE]\n\n")
	})

	t.Run("Stream API error response", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			errorResp := map[string]interface{}{
				"type": "error",
				"error": map[string]string{
					"type":    "invalid_request_error",
					"message": "Bad request to stream",
				},
			}
			json.NewEncoder(w).Encode(errorResp)
		}
		adapter, _, cleanup := setupAnthropicAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{Model: "claude-2", Messages: []ChatMessage{{Role: "user", Content: "Hi"}}, Stream: true, MaxTokens: 10}
		var streamOutput bytes.Buffer
		err := adapter.StreamChatCompletion(context.Background(), req, &streamOutput)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Anthropic API stream request failed with status 400")
		assert.Contains(t, err.Error(), "Bad request to stream")
	})
}

func TestAnthropicAdapter_HealthCheck(t *testing.T) {
	t.Run("Successful health check with API key", func(t *testing.T) {
		adapter, _, cleanup := setupAnthropicAdapterTest(t, nil)
		defer cleanup()
		require.NotEmpty(t, adapter.apiKey, "Test setup should provide an API key")
		err := adapter.HealthCheck(context.Background())
		require.NoError(t, err)
	})

	t.Run("Failed health check without API key", func(t *testing.T) {
		mockSR := &mockSecretRetriever{secrets: make(map[string]string)}
		cfg := config.ProviderConfig{
			ID:        "test-anthropic-no-key-hc",
			Name:      "TestAnthropicNoKeyHC",
			Type:      config.ProviderTypeLLM,
			LLMConfig: &config.LLMProviderConfig{APIBase: "http://localhost:1234"},
		}
		adapter, errConstruct := NewAnthropicAdapter(cfg, mockSR, nil)
		require.NoError(t, errConstruct)
		require.NotNil(t, adapter)
		require.Empty(t, adapter.apiKey, "Adapter API key should be empty for this test case")

		errHealthCheck := adapter.HealthCheck(context.Background())
		require.Error(t, errHealthCheck)
		assert.Contains(t, errHealthCheck.Error(), "Anthropic API key is not configured")
	})
}

func TestAnthropicAdapter_NotImplementedMethods(t *testing.T) {
	adapter, _, cleanup := setupAnthropicAdapterTest(t, nil)
	defer cleanup()

	t.Run("GenerateEmbedding", func(t *testing.T) {
		_, err := adapter.GenerateEmbedding(context.Background(), &EmbeddingRequest{Model: "text-embedding-ada-002", Input: "test"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "embedding generation is not directly supported")
	})

	t.Run("AudioTranscription", func(t *testing.T) {
		_, err := adapter.AudioTranscription(context.Background(), &AudioTranscriptionRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audio transcription not supported")
	})

	t.Run("TextToSpeech", func(t *testing.T) {
		err := adapter.TextToSpeech(context.Background(), &TextToSpeechRequest{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "text-to-speech not supported")
	})

	t.Run("InvokeTool", func(t *testing.T) {
		_, err := adapter.InvokeTool(context.Background(), &ToolInvocationRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "direct tool invocation not supported")
	})

	t.Run("StreamInvokeTool", func(t *testing.T) {
		err := adapter.StreamInvokeTool(context.Background(), nil, make(chan *ToolInvocationStreamChunk)) // Ensure responseStream is not nil
		require.Error(t, err)
		assert.Contains(t, err.Error(), "streaming tool invocation not supported")
	})
}
