package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openpons/gateway/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretRetriever is defined in provider_test_helpers.go

func TestNewOpenAIAdapter(t *testing.T) {
	mockSR := &mockSecretRetriever{secrets: make(map[string]string)}
	mockSR.secrets["test-secret-id"] = "test-api-key"

	t.Run("Successful creation", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "p1",
			Name:                "openai-test",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "test-secret-id",
			LLMConfig:           &config.LLMProviderConfig{APIBase: "https://api.openai.com/v1"},
		}
		adapter, err := NewOpenAIAdapter(cfg, mockSR, nil)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, "test-api-key", adapter.apiKey)
		assert.Equal(t, "openai-test", adapter.name)
	})

	t.Run("Missing LLMConfig", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "p2",
			Name:                "openai-no-llm-config",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "test-secret-id",
		}
		_, err := NewOpenAIAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "openai adapter requires LLMConfig to be set")
	})

	t.Run("Secret retrieval error", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:                  "p3",
			Name:                "openai-secret-error",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "nonexistent-secret",
			LLMConfig:           &config.LLMProviderConfig{},
		}
		_, err := NewOpenAIAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve API key")
	})

	t.Run("Empty API key", func(t *testing.T) {
		mockSR.secrets["empty-secret"] = ""
		cfg := config.ProviderConfig{
			ID:                  "p4",
			Name:                "openai-empty-key",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "empty-secret",
			LLMConfig:           &config.LLMProviderConfig{},
		}
		_, err := NewOpenAIAdapter(cfg, mockSR, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "retrieved API key for OpenAI provider")
		assert.Contains(t, err.Error(), "is empty")
		delete(mockSR.secrets, "empty-secret") // cleanup
	})

	t.Run("No secret ID provided", func(t *testing.T) {
		cfg := config.ProviderConfig{
			ID:        "p5",
			Name:      "openai-no-secret-id",
			Type:      config.ProviderTypeLLM,
			LLMConfig: &config.LLMProviderConfig{},
		}
		// Expects a log warning but not an error from NewOpenAIAdapter itself
		adapter, err := NewOpenAIAdapter(cfg, mockSR, nil)
		require.NoError(t, err) // Should not error, just log a warning
		require.NotNil(t, adapter)
		assert.Equal(t, "", adapter.apiKey)
	})
}

func TestOpenAIAdapter_Init(t *testing.T) {
	mockSR := &mockSecretRetriever{secrets: make(map[string]string)}
	mockSR.secrets["init-secret"] = "init-key"

	baseCfg := config.ProviderConfig{
		ID: "p-init", Name: "openai-init-test", Type: config.ProviderTypeLLM,
		LLMConfig: &config.LLMProviderConfig{APIBase: "https://api.openai.com/v1"},
	}
	adapter, err := NewOpenAIAdapter(baseCfg, mockSR, nil) // No secret ID initially
	require.NoError(t, err)
	require.Equal(t, "", adapter.apiKey)

	t.Run("Successful Init with new secret", func(t *testing.T) {
		newCfg := baseCfg
		newCfg.CredentialsSecretID = "init-secret"
		err := adapter.Init(&newCfg, mockSR)
		require.NoError(t, err)
		assert.Equal(t, "init-key", adapter.apiKey)
		assert.Equal(t, newCfg.ID, adapter.id)
		assert.Equal(t, newCfg.Name, adapter.name)
	})

	t.Run("Init with missing secret", func(t *testing.T) {
		failCfg := baseCfg
		failCfg.CredentialsSecretID = "missing-init-secret"
		err := adapter.Init(&failCfg, mockSR)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve API key")
	})
}

// Helper to setup a test server and an OpenAIAdapter pointing to it
func setupOpenAIAdapterTest(t *testing.T, handler http.HandlerFunc) (*OpenAIAdapter, *httptest.Server, func()) {
	server := httptest.NewServer(handler)

	mockSR := &mockSecretRetriever{secrets: map[string]string{"test-key": "fake-api-key"}}
	cfg := config.ProviderConfig{
		ID:                  "test-openai-provider",
		Name:                "TestOpenAI",
		Type:                config.ProviderTypeLLM,
		CredentialsSecretID: "test-key",
		LLMConfig:           &config.LLMProviderConfig{APIBase: server.URL},
	}

	adapter, err := NewOpenAIAdapter(cfg, mockSR, server.Client())
	require.NoError(t, err)
	require.NotNil(t, adapter)

	cleanup := func() {
		server.Close()
	}
	return adapter, server, cleanup
}

func TestOpenAIAdapter_ChatCompletion(t *testing.T) {
	t.Run("Successful chat completion", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/chat/completions", r.URL.Path)
			assert.Equal(t, "Bearer fake-api-key", r.Header.Get("Authorization"))

			var reqBody ChatCompletionRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "gpt-4", reqBody.Model)

			resp := openaiAPICompletionResponse{
				ID:      "chatcmpl-123",
				Object:  "chat.completion",
				Created: time.Now().Unix(),
				Model:   "gpt-4-0613",
				Choices: []openaiAPIChoice{
					{Index: 0, Message: openaiAPIMessage{Role: "assistant", Content: "Hello!"}, FinishReason: "stop"},
				},
				Usage: &openaiAPIUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
			}
			json.NewEncoder(w).Encode(resp)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{Model: "gpt-4", Messages: []ChatMessage{{Role: "user", Content: "Hi"}}}
		resp, err := adapter.ChatCompletion(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "chatcmpl-123", resp.ID)
		require.Len(t, resp.Choices, 1)
		assert.Equal(t, "assistant", resp.Choices[0].Message.Role)
		assert.Equal(t, "Hello!", resp.Choices[0].Message.Content)
		require.NotNil(t, resp.Usage)
		assert.Equal(t, 15, resp.Usage.TotalTokens)
	})

	t.Run("Successful chat completion with tool calls", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			var reqBody ChatCompletionRequestWithTools // Assuming a type that includes tools
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "gpt-4-tools", reqBody.Model)
			require.Len(t, reqBody.Tools, 1)
			assert.Equal(t, "function", reqBody.Tools[0].Type)
			assert.Equal(t, "get_weather", reqBody.Tools[0].Function.Name)

			resp := openaiAPICompletionResponse{
				ID:      "chatcmpl-tools-123",
				Object:  "chat.completion",
				Created: time.Now().Unix(),
				Model:   "gpt-4-tools-0613",
				Choices: []openaiAPIChoice{
					{
						Index: 0,
						Message: openaiAPIMessage{
							Role: "assistant",
							ToolCalls: []openaiAPIToolCall{
								{
									ID:   "call_123",
									Type: "function",
									Function: openaiAPIFunctionCall{
										Name:      "get_weather",
										Arguments: `{"location": "Boston"}`,
									},
								},
							},
						},
						FinishReason: "tool_calls",
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		// Define a request that includes tools
		req := &ChatCompletionRequest{
			Model: "gpt-4-tools",
			Messages: []ChatMessage{
				{Role: "user", Content: "What's the weather in Boston?"},
			},
			Tools: []Tool{
				{
					Type: "function",
					Function: FunctionDefinition{
						Name:        "get_weather",
						Description: "Get current weather for a location",
						Parameters:  json.RawMessage(`{"type": "object", "properties": {"location": {"type": "string"}}}`),
					},
				},
			},
		}

		resp, err := adapter.ChatCompletion(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "chatcmpl-tools-123", resp.ID)
		require.Len(t, resp.Choices, 1)
		assert.Equal(t, "assistant", resp.Choices[0].Message.Role)
		assert.Equal(t, "", resp.Choices[0].Message.Content) // Content is empty when tool_calls are present
		require.Len(t, resp.Choices[0].Message.ToolCalls, 1)
		toolCall := resp.Choices[0].Message.ToolCalls[0]
		assert.Equal(t, "call_123", toolCall.ID)
		assert.Equal(t, "function", toolCall.Type)
		assert.Equal(t, "get_weather", toolCall.Function.Name)
		assert.JSONEq(t, `{"location": "Boston"}`, toolCall.Function.Arguments)
		assert.Equal(t, "tool_calls", resp.Choices[0].FinishReason)
	})

	t.Run("API error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error": {"message": "Incorrect API key provided"}}`)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{Model: "gpt-4", Messages: []ChatMessage{{Role: "user", Content: "Hi"}}}
		_, err := adapter.ChatCompletion(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OpenAI API request failed with status 401")
		assert.Contains(t, err.Error(), "Incorrect API key provided")
	})
}

// ChatCompletionRequestWithTools is a helper struct for testing requests that include tools.
// This mirrors the structure that the OpenAI API expects when tools are involved.
type ChatCompletionRequestWithTools struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Tools    []Tool        `json:"tools,omitempty"`
	Stream   bool          `json:"stream,omitempty"`
	// Add other fields like temperature, max_tokens etc. if needed for test variations
}

func TestOpenAIAdapter_GenerateEmbedding(t *testing.T) {
	t.Run("Successful embedding generation", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/embeddings", r.URL.Path)
			assert.Equal(t, "Bearer fake-api-key", r.Header.Get("Authorization"))

			var reqBody EmbeddingRequest // Using internal EmbeddingRequest as OpenAI's is similar
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "text-embedding-ada-002", reqBody.Model)
			assert.Equal(t, "test input", reqBody.Input)

			// OpenAI API embedding response structure
			type openaiAPIEmbedding struct {
				Object    string    `json:"object"`
				Embedding []float32 `json:"embedding"`
				Index     int       `json:"index"`
			}
			type openaiAPIEmbeddingResponse struct {
				Object string               `json:"object"`
				Data   []openaiAPIEmbedding `json:"data"`
				Model  string               `json:"model"`
				Usage  openaiAPIUsage       `json:"usage"`
			}

			resp := openaiAPIEmbeddingResponse{
				Object: "list",
				Data: []openaiAPIEmbedding{
					{Object: "embedding", Embedding: []float32{0.1, 0.2, 0.3}, Index: 0},
				},
				Model: "text-embedding-ada-002",
				Usage: openaiAPIUsage{PromptTokens: 8, TotalTokens: 8},
			}
			json.NewEncoder(w).Encode(resp)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		req := &EmbeddingRequest{Model: "text-embedding-ada-002", Input: "test input"}
		resp, err := adapter.GenerateEmbedding(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "list", resp.Object)
		require.Len(t, resp.Data, 1)
		assert.Equal(t, "text-embedding-ada-002", resp.Model)
		assert.Equal(t, []float32{0.1, 0.2, 0.3}, resp.Data[0].Embedding)
		assert.Equal(t, 8, resp.Usage.TotalTokens)
	})

	t.Run("Embedding API error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			// Use io.WriteString or fmt.Fprint for simple string responses
			// For JSON error response:
			// w.Header().Set("Content-Type", "application/json")
			// json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"message": "Invalid request"}})
			fmt.Fprint(w, `{"error": {"message": "Invalid request for embedding"}}`)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		req := &EmbeddingRequest{Model: "text-embedding-ada-002", Input: "test input"}
		_, err := adapter.GenerateEmbedding(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OpenAI embedding API request failed with status 400")
		assert.Contains(t, err.Error(), "Invalid request for embedding")
	})
}

func TestOpenAIAdapter_StreamChatCompletion(t *testing.T) {
	t.Run("Successful stream chat completion", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.True(t, r.URL.Path == "/chat/completions" || r.URL.Path == "/v1/chat/completions") // Azure might use /v1/
			assert.Equal(t, "Bearer fake-api-key", r.Header.Get("Authorization"))

			var reqBody ChatCompletionRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.True(t, reqBody.Stream, "Stream field should be true for streaming requests")

			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			// Simulate a few stream chunks
			chunk1 := `{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-4-0613","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`
			chunk2 := `{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-4-0613","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`
			chunk3 := `{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-4-0613","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":null}]}`
			chunk4 := `{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-4-0613","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`

			fmt.Fprintf(w, "data: %s\n\n", chunk1)
			fmt.Fprintf(w, "data: %s\n\n", chunk2)
			fmt.Fprintf(w, "data: %s\n\n", chunk3)
			fmt.Fprintf(w, "data: %s\n\n", chunk4)
			fmt.Fprintf(w, "data: [DONE]\n\n") // OpenAI specific termination
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{Model: "gpt-4", Messages: []ChatMessage{{Role: "user", Content: "Hi"}}, Stream: true}
		var streamOutput bytes.Buffer

		err := adapter.StreamChatCompletion(context.Background(), req, &streamOutput)
		require.NoError(t, err)

		// Verify the raw stream output contains the expected data.
		// A more robust test would parse the SSE events.
		outputStr := streamOutput.String()
		assert.Contains(t, outputStr, `"role":"assistant"`)
		assert.Contains(t, outputStr, `"content":"Hello"`)
		assert.Contains(t, outputStr, `"content":" world"`)
		assert.Contains(t, outputStr, `"finish_reason":"stop"`)
		assert.Contains(t, outputStr, "data: [DONE]")
	})

	t.Run("Stream API error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json") // Error might not be event-stream
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error": {"message": "Stream failed"}}`)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		req := &ChatCompletionRequest{Model: "gpt-4", Messages: []ChatMessage{{Role: "user", Content: "Hi"}}, Stream: true}
		var streamOutput bytes.Buffer
		err := adapter.StreamChatCompletion(context.Background(), req, &streamOutput)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OpenAI API stream request failed with status 500")
		assert.Contains(t, err.Error(), "Stream failed")
	})
}

func TestOpenAIAdapter_AudioTranscription(t *testing.T) {
	t.Run("Successful audio transcription", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/audio/transcriptions", r.URL.Path)

			err := r.ParseMultipartForm(32 << 20) // 32MB max memory
			require.NoError(t, err)

			file, _, err := r.FormFile("file")
			require.NoError(t, err)
			defer file.Close()

			fileBytes, err := io.ReadAll(file)
			require.NoError(t, err)
			assert.Equal(t, "fake audio data", string(fileBytes))

			assert.Equal(t, "whisper-1", r.FormValue("model"))
			assert.Equal(t, "en", r.FormValue("language"))

			// OpenAI API audio transcription response structure
			resp := AudioTranscriptionResponse{ // Using internal struct as it mirrors OpenAI's
				Text:     "This is a test transcription.",
				Language: "en",
				Duration: 1.23,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		mockAudioFile := bytes.NewReader([]byte("fake audio data"))
		req := &AudioTranscriptionRequest{
			File:     mockAudioFile,
			FileName: "test.mp3",
			Model:    "whisper-1",
			Language: "en",
		}

		resp, err := adapter.AudioTranscription(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "This is a test transcription.", resp.Text)
		assert.Equal(t, "en", resp.Language)
	})

	t.Run("AudioTranscription API error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error": {"message": "Permission denied"}}`)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		mockAudioFile := bytes.NewReader([]byte("fake audio data"))
		req := &AudioTranscriptionRequest{
			File:     mockAudioFile,
			FileName: "test.mp3",
			Model:    "whisper-1",
		}
		_, err := adapter.AudioTranscription(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OpenAI transcription API request failed with status 403")
	})

	t.Run("AudioTranscription no file", func(t *testing.T) {
		adapter, _, cleanup := setupOpenAIAdapterTest(t, nil) // Handler not strictly needed as it should fail before HTTP
		defer cleanup()

		req := &AudioTranscriptionRequest{
			File:     nil, // No file
			FileName: "test.mp3",
			Model:    "whisper-1",
		}
		_, err := adapter.AudioTranscription(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audio file (request.File) is required for transcription")
	})
}

func TestOpenAIAdapter_TextToSpeech(t *testing.T) {
	t.Run("Successful text to speech", func(t *testing.T) {
		mockAudioData := []byte("fake-tts-audio-data-mp3")
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/audio/speech", r.URL.Path)

			var reqBody struct { // Based on openaiTTSReq in openai.go
				Model          string  `json:"model"`
				Input          string  `json:"input"`
				Voice          string  `json:"voice"`
				ResponseFormat string  `json:"response_format,omitempty"`
				Speed          float32 `json:"speed,omitempty"`
			}
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "tts-1", reqBody.Model)
			assert.Equal(t, "Hello world", reqBody.Input)
			assert.Equal(t, "alloy", reqBody.Voice)

			w.Header().Set("Content-Type", "audio/mpeg")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(mockAudioData)
			require.NoError(t, err)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		req := &TextToSpeechRequest{
			Model: "tts-1",
			Input: "Hello world",
			Voice: "alloy",
		}
		var audioOutput bytes.Buffer
		err := adapter.TextToSpeech(context.Background(), req, &audioOutput)
		require.NoError(t, err)
		assert.Equal(t, mockAudioData, audioOutput.Bytes())
	})

	t.Run("TextToSpeech API error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error": {"message": "Invalid voice"}}`)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		req := &TextToSpeechRequest{Model: "tts-1", Input: "Hello", Voice: "invalid-voice"}
		var audioOutput bytes.Buffer
		err := adapter.TextToSpeech(context.Background(), req, &audioOutput)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OpenAI TTS API request failed with status 400")
	})

	t.Run("TextToSpeech missing voice", func(t *testing.T) {
		adapter, _, cleanup := setupOpenAIAdapterTest(t, nil) // Handler not strictly needed
		defer cleanup()

		req := &TextToSpeechRequest{Model: "tts-1", Input: "Hello"} // Missing Voice
		var audioOutput bytes.Buffer
		err := adapter.TextToSpeech(context.Background(), req, &audioOutput)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "voice is required for TextToSpeech")
	})
}

func TestOpenAIAdapter_HealthCheck(t *testing.T) {
	t.Run("Successful health check", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/models", r.URL.Path) // OpenAI health check often uses /models
			assert.Equal(t, "Bearer fake-api-key", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
			// Optionally return a minimal valid /models response if the adapter parses it
			fmt.Fprint(w, `{"data": [], "object": "list"}`)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		err := adapter.HealthCheck(context.Background())
		require.NoError(t, err)
	})

	t.Run("Failed health check - API error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error": {"message": "Server error"}}`)
		}
		adapter, _, cleanup := setupOpenAIAdapterTest(t, handler)
		defer cleanup()

		err := adapter.HealthCheck(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OpenAI API health check failed with status 500")
	})

	t.Run("Failed health check - no API key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// This handler should not be called if API key is missing
			t.Error("HTTP handler called unexpectedly when API key is missing for health check")
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		mockSR := &mockSecretRetriever{secrets: map[string]string{}} // No "test-key"
		cfg := config.ProviderConfig{
			ID:                  "test-openai-no-key-hc",
			Name:                "TestOpenAINoKeyHC",
			Type:                config.ProviderTypeLLM,
			CredentialsSecretID: "test-key", // This key won't be found in mockSR
			LLMConfig:           &config.LLMProviderConfig{APIBase: server.URL},
		}
		// Create adapter directly to control secret retriever
		_, errConstruct := NewOpenAIAdapter(cfg, mockSR, server.Client()) // adapter variable unused
		// NewOpenAIAdapter will error if secret is not found and CredentialsSecretID is set
		require.Error(t, errConstruct, "NewOpenAIAdapter should fail if secret is specified but not found")

		// To test HealthCheck's internal API key check, we need an adapter where apiKey is explicitly empty.
		// This means CredentialsSecretID was not set in the first place.
		cfgNoSecretID := config.ProviderConfig{
			ID:        "test-openai-no-secret-id-hc",
			Name:      "TestOpenAINoSecretIDHC",
			Type:      config.ProviderTypeLLM,
			LLMConfig: &config.LLMProviderConfig{APIBase: server.URL},
			// CredentialsSecretID is omitted
		}
		adapterNoKey, errNoKeyConstruct := NewOpenAIAdapter(cfgNoSecretID, mockSR, server.Client())
		require.NoError(t, errNoKeyConstruct) // Construction is fine, apiKey will be ""
		require.NotNil(t, adapterNoKey)

		errHealthCheck := adapterNoKey.HealthCheck(context.Background())
		require.Error(t, errHealthCheck)
		assert.Contains(t, errHealthCheck.Error(), "OpenAI API key is not configured")
	})
}

func TestOpenAIAdapter_ProviderInfo(t *testing.T) {
	adapter, _, cleanup := setupOpenAIAdapterTest(t, nil)
	defer cleanup()
	info := adapter.ProviderInfo()
	assert.Equal(t, "TestOpenAI", info.Name)
	assert.Equal(t, config.ProviderTypeLLM, info.Type)
	assert.Contains(t, info.Capabilities, "chat_completion")
}

func TestOpenAIAdapter_GetConfig(t *testing.T) {
	adapter, _, cleanup := setupOpenAIAdapterTest(t, nil)
	defer cleanup()
	cfg := adapter.GetConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, "test-openai-provider", cfg.ID)
}

func TestOpenAIAdapter_Shutdown(t *testing.T) {
	adapter, _, cleanup := setupOpenAIAdapterTest(t, nil)
	defer cleanup()
	err := adapter.Shutdown() // Should be a no-op for this adapter
	assert.NoError(t, err)
}
