package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart" // Needed for AudioTranscription
	"net/http"
	"sync"

	"github.com/openpons/gateway/internal/config"
)

var _ ProviderAdapter = (*OpenAIAdapter)(nil)

// --- OpenAI API specific response structures ---
type openaiAPIFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openaiAPIToolCall struct {
	ID       string                `json:"id"`
	Type     string                `json:"type"`
	Function openaiAPIFunctionCall `json:"function"`
}

type openaiAPIMessage struct {
	Role       string              `json:"role"`
	Content    string              `json:"content"`
	Name       *string             `json:"name,omitempty"`
	ToolCalls  []openaiAPIToolCall `json:"tool_calls,omitempty"`
	ToolCallID *string             `json:"tool_call_id,omitempty"`
}

type openaiAPIChoice struct {
	Index        int              `json:"index"`
	Message      openaiAPIMessage `json:"message"`
	FinishReason string           `json:"finish_reason"`
}

type openaiAPIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openaiAPICompletionResponse struct {
	ID                string            `json:"id"`
	Object            string            `json:"object"`
	Created           int64             `json:"created"`
	Model             string            `json:"model"`
	Choices           []openaiAPIChoice `json:"choices"`
	Usage             *openaiAPIUsage   `json:"usage,omitempty"`
	SystemFingerprint string            `json:"system_fingerprint,omitempty"`
}

// --- End of OpenAI API specific response structures ---

type OpenAIAdapter struct {
	id            string
	name          string
	cfg           config.ProviderConfig
	secretManager SecretRetriever // Use interface
	apiKey        string
	httpClient    *http.Client
	shutdownMutex sync.Mutex
	isShutdown    bool
}

func NewOpenAIAdapter(providerCfg config.ProviderConfig, sm SecretRetriever, httpClient *http.Client) (*OpenAIAdapter, error) {
	if providerCfg.LLMConfig == nil {
		return nil, fmt.Errorf("openai adapter requires LLMConfig to be set")
	}

	var apiKeyVal string
	var err error
	if providerCfg.CredentialsSecretID != "" {
		apiKeyVal, err = sm.GetSecret(context.Background(), providerCfg.CredentialsSecretID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve API key for OpenAI provider %s (secretID: %s): %w", providerCfg.Name, providerCfg.CredentialsSecretID, err)
		}
		if apiKeyVal == "" {
			return nil, fmt.Errorf("retrieved API key for OpenAI provider %s (secretID: %s) is empty", providerCfg.Name, providerCfg.CredentialsSecretID)
		}
	} else {
		log.Printf("Warning: No CredentialsSecretID configured for OpenAI provider %s. API key will be empty.", providerCfg.Name)
	}

	clientToUse := httpClient
	if clientToUse == nil {
		clientToUse = http.DefaultClient
	}

	return &OpenAIAdapter{
		id:            providerCfg.ID,
		name:          providerCfg.Name,
		cfg:           providerCfg,
		secretManager: sm,
		apiKey:        apiKeyVal,
		httpClient:    clientToUse,
		isShutdown:    false,
	}, nil
}

// Init initializes the adapter. For OpenAIAdapter, it's mostly done in NewOpenAIAdapter.
func (a *OpenAIAdapter) Init(cfg *config.ProviderConfig, sr SecretRetriever) error {
	// This adapter is initialized via NewOpenAIAdapter, but we can re-affirm or update if needed.
	if cfg == nil {
		return fmt.Errorf("provider config cannot be nil for Init")
	}
	if sr == nil {
		return fmt.Errorf("secret retriever cannot be nil for Init")
	}

	a.shutdownMutex.Lock()
	defer a.shutdownMutex.Unlock()

	if a.isShutdown {
		return fmt.Errorf("cannot reinitialize a shutdown OpenAI adapter")
	}

	a.cfg = *cfg // Update config
	a.secretManager = sr
	a.id = cfg.ID
	a.name = cfg.Name

	if cfg.CredentialsSecretID != "" {
		apiKeyVal, err := sr.GetSecret(context.Background(), cfg.CredentialsSecretID)
		if err != nil {
			return fmt.Errorf("Init: failed to retrieve API key for OpenAI provider %s (secretID: %s): %w", cfg.Name, cfg.CredentialsSecretID, err)
		}
		if apiKeyVal == "" {
			return fmt.Errorf("Init: retrieved API key for OpenAI provider %s (secretID: %s) is empty", cfg.Name, cfg.CredentialsSecretID)
		}
		a.apiKey = apiKeyVal
	} else {
		log.Printf("Warning (Init): No CredentialsSecretID configured for OpenAI provider %s. API key may be empty.", cfg.Name)
		a.apiKey = "" // Ensure it's reset if config changes
	}
	return nil
}

func (a *OpenAIAdapter) ProviderInfo() Info {
	return Info{
		Name: a.name,
		Type: config.ProviderTypeLLM,
		Capabilities: []string{
			"chat_completion",
			"stream_chat_completion",
			"embedding",
			"audio_transcription",
			"text_to_speech",
		},
	}
}

func (a *OpenAIAdapter) GetConfig() *config.ProviderConfig {
	return &a.cfg
}

func (a *OpenAIAdapter) ChatCompletion(ctx context.Context, request *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return nil, fmt.Errorf("OpenAI adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if request == nil {
		return nil, fmt.Errorf("ChatCompletionRequest cannot be nil")
	}
	if a.apiKey == "" {
		return nil, fmt.Errorf("OpenAI API key is not configured for provider %s", a.name)
	}

	apiBase := a.cfg.LLMConfig.APIBase
	if apiBase == "" {
		apiBase = "https://api.openai.com/v1"
	}
	endpoint := apiBase + "/chat/completions"

	reqBodyBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OpenAI request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAI HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	if a.cfg.LLMConfig.AzureAPIVersion != "" && a.cfg.LLMConfig.AzureAPIType == "azure" {
		httpReq.Header.Set("api-key", a.apiKey)
		httpReq.Header.Del("Authorization")
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to OpenAI API: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("OpenAI API request failed with status %d: %s", httpResp.StatusCode, string(bodyBytes))
	}

	var apiResp openaiAPICompletionResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode OpenAI API response: %w", err)
	}

	internalResp := ChatCompletionResponse{
		ID:                apiResp.ID,
		Object:            apiResp.Object,
		Created:           apiResp.Created,
		Model:             apiResp.Model,
		SystemFingerprint: apiResp.SystemFingerprint,
	}
	if apiResp.Usage != nil {
		internalResp.Usage = &UsageStats{
			PromptTokens:     apiResp.Usage.PromptTokens,
			CompletionTokens: apiResp.Usage.CompletionTokens,
			TotalTokens:      apiResp.Usage.TotalTokens,
		}
	}
	internalResp.Choices = make([]ChatCompletionResponseChoice, len(apiResp.Choices))
	for i, choice := range apiResp.Choices {
		internalChoice := ChatCompletionResponseChoice{
			Index:        choice.Index,
			FinishReason: choice.FinishReason,
			Message:      ChatMessage{Role: choice.Message.Role, Content: choice.Message.Content},
		}
		if choice.Message.Name != nil {
			internalChoice.Message.Name = *choice.Message.Name
		}
		if choice.Message.ToolCallID != nil {
			internalChoice.Message.ToolCallID = *choice.Message.ToolCallID
		}
		if len(choice.Message.ToolCalls) > 0 {
			internalChoice.Message.ToolCalls = make([]ToolCall, len(choice.Message.ToolCalls))
			for j, tc := range choice.Message.ToolCalls {
				internalChoice.Message.ToolCalls[j] = ToolCall{
					ID:       tc.ID,
					Type:     tc.Type,
					Function: FunctionCall{Name: tc.Function.Name, Arguments: tc.Function.Arguments},
				}
			}
		}
		internalResp.Choices[i] = internalChoice
	}
	log.Printf("OpenAIAdapter: Successfully completed ChatCompletion for model %s", request.Model)
	return &internalResp, nil
}

func (a *OpenAIAdapter) StreamChatCompletion(ctx context.Context, request *ChatCompletionRequest, stream io.Writer) error {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return fmt.Errorf("OpenAI adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if request == nil {
		return fmt.Errorf("ChatCompletionRequest cannot be nil")
	}
	if a.apiKey == "" {
		return fmt.Errorf("OpenAI API key is not configured for provider %s", a.name)
	}
	if !request.Stream {
		request.Stream = true
	}

	apiBase := a.cfg.LLMConfig.APIBase
	if apiBase == "" {
		apiBase = "https://api.openai.com/v1"
	}
	endpoint := apiBase + "/chat/completions"

	reqBodyBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal OpenAI stream request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create OpenAI stream HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	httpReq.Header.Set("Accept", "text/event-stream")
	if a.cfg.LLMConfig.AzureAPIVersion != "" && a.cfg.LLMConfig.AzureAPIType == "azure" {
		httpReq.Header.Set("api-key", a.apiKey)
		httpReq.Header.Del("Authorization")
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send stream request to OpenAI API: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("OpenAI API stream request failed with status %d: %s", httpResp.StatusCode, string(bodyBytes))
	}

	written, err := io.Copy(stream, httpResp.Body)
	if err != nil {
		log.Printf("Error copying stream from OpenAI to output: %v (copied %d bytes)", err, written)
		return fmt.Errorf("error streaming response from OpenAI: %w", err)
	}
	log.Printf("OpenAIAdapter: StreamChatCompletion for model %s completed, copied %d bytes.", request.Model, written)
	return nil
}

func (a *OpenAIAdapter) GenerateEmbedding(ctx context.Context, request *EmbeddingRequest) (*EmbeddingResponse, error) {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return nil, fmt.Errorf("OpenAI adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if request == nil {
		return nil, fmt.Errorf("EmbeddingRequest cannot be nil")
	}
	if a.apiKey == "" {
		return nil, fmt.Errorf("OpenAI API key is not configured for provider %s", a.name)
	}

	apiBase := a.cfg.LLMConfig.APIBase
	if apiBase == "" {
		apiBase = "https://api.openai.com/v1"
	}
	endpoint := apiBase + "/embeddings"

	reqBodyBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OpenAI embedding request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAI embedding HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	if a.cfg.LLMConfig.AzureAPIVersion != "" && a.cfg.LLMConfig.AzureAPIType == "azure" {
		httpReq.Header.Set("api-key", a.apiKey)
		httpReq.Header.Del("Authorization")
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to OpenAI embedding API: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("OpenAI embedding API request failed with status %d: %s", httpResp.StatusCode, string(bodyBytes))
	}

	var openAIResp EmbeddingResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&openAIResp); err != nil {
		return nil, fmt.Errorf("failed to decode OpenAI embedding API response: %w", err)
	}
	log.Printf("OpenAIAdapter: Successfully generated embedding for model %s", request.Model)
	return &openAIResp, nil
}

func (a *OpenAIAdapter) AudioTranscription(ctx context.Context, request *AudioTranscriptionRequest) (*AudioTranscriptionResponse, error) {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return nil, fmt.Errorf("OpenAI adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if request == nil {
		return nil, fmt.Errorf("AudioTranscriptionRequest cannot be nil")
	}
	if a.apiKey == "" {
		return nil, fmt.Errorf("OpenAI API key is not configured for provider %s", a.name)
	}

	apiBase := a.cfg.LLMConfig.APIBase
	if apiBase == "" {
		apiBase = "https://api.openai.com/v1"
	}
	endpoint := apiBase + "/audio/transcriptions"

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if request.File == nil {
		return nil, fmt.Errorf("audio file (request.File) is required for transcription")
	}
	part, err := writer.CreateFormFile("file", request.FileName)
	if err != nil {
		return nil, fmt.Errorf("failed to create form file for audio: %w", err)
	}
	if _, err = io.Copy(part, request.File); err != nil {
		return nil, fmt.Errorf("failed to copy audio file to form: %w", err)
	}

	model := request.Model
	if model == "" {
		model = "whisper-1"
	}
	if err = writer.WriteField("model", model); err != nil {
		return nil, fmt.Errorf("failed to write model field: %w", err)
	}

	if request.Language != "" {
		if err = writer.WriteField("language", request.Language); err != nil {
			return nil, fmt.Errorf("failed to write language field: %w", err)
		}
	}
	if request.Prompt != "" {
		if err = writer.WriteField("prompt", request.Prompt); err != nil {
			return nil, fmt.Errorf("failed to write prompt field: %w", err)
		}
	}
	if request.ResponseFormat != "" {
		if err = writer.WriteField("response_format", request.ResponseFormat); err != nil {
			return nil, fmt.Errorf("failed to write response_format field: %w", err)
		}
	}
	if request.Temperature != 0 {
		if err = writer.WriteField("temperature", fmt.Sprintf("%f", request.Temperature)); err != nil {
			return nil, fmt.Errorf("failed to write temperature field: %w", err)
		}
	}

	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAI transcription HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", writer.FormDataContentType())
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	if a.cfg.LLMConfig.AzureAPIVersion != "" && a.cfg.LLMConfig.AzureAPIType == "azure" {
		httpReq.Header.Set("api-key", a.apiKey)
		httpReq.Header.Del("Authorization")
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to OpenAI transcription API: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBodyBytes, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("OpenAI transcription API request failed with status %d: %s", httpResp.StatusCode, string(respBodyBytes))
	}

	var openAIResp AudioTranscriptionResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&openAIResp); err != nil {
		return nil, fmt.Errorf("failed to decode OpenAI transcription API response: %w", err)
	}
	log.Printf("OpenAIAdapter: Successfully transcribed audio with model %s", model)
	return &openAIResp, nil
}

func (a *OpenAIAdapter) TextToSpeech(ctx context.Context, request *TextToSpeechRequest, stream io.Writer) error {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return fmt.Errorf("OpenAI adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if request == nil {
		return fmt.Errorf("TextToSpeechRequest cannot be nil")
	}
	if a.apiKey == "" {
		return fmt.Errorf("OpenAI API key is not configured for provider %s", a.name)
	}

	apiBase := a.cfg.LLMConfig.APIBase
	if apiBase == "" {
		apiBase = "https://api.openai.com/v1"
	}
	endpoint := apiBase + "/audio/speech"

	openaiTTSReq := struct {
		Model          string  `json:"model"`
		Input          string  `json:"input"`
		Voice          string  `json:"voice"`
		ResponseFormat string  `json:"response_format,omitempty"`
		Speed          float32 `json:"speed,omitempty"`
	}{
		Model:          request.Model,
		Input:          request.Input,
		Voice:          request.Voice,
		ResponseFormat: request.ResponseFormat,
		Speed:          request.Speed,
	}
	if openaiTTSReq.Model == "" {
		openaiTTSReq.Model = "tts-1"
	}
	if openaiTTSReq.Voice == "" {
		return fmt.Errorf("voice is required for TextToSpeech")
	}

	reqBodyBytes, err := json.Marshal(openaiTTSReq)
	if err != nil {
		return fmt.Errorf("failed to marshal OpenAI TTS request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create OpenAI TTS HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	if a.cfg.LLMConfig.AzureAPIVersion != "" && a.cfg.LLMConfig.AzureAPIType == "azure" {
		httpReq.Header.Set("api-key", a.apiKey)
		httpReq.Header.Del("Authorization")
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request to OpenAI TTS API: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBodyBytes, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("OpenAI TTS API request failed with status %d: %s", httpResp.StatusCode, string(respBodyBytes))
	}

	written, err := io.Copy(stream, httpResp.Body)
	if err != nil {
		log.Printf("Error copying TTS stream from OpenAI to output: %v (copied %d bytes)", err, written)
		return fmt.Errorf("error streaming TTS response from OpenAI: %w", err)
	}
	log.Printf("OpenAIAdapter: TextToSpeech for model %s completed, copied %d bytes.", request.Model, written)
	return nil
}

func (a *OpenAIAdapter) InvokeTool(ctx context.Context, request *ToolInvocationRequest) (*ToolInvocationResponse, error) {
	return nil, fmt.Errorf("OpenAIAdapter does not support InvokeTool directly as an LLM provider")
}

func (a *OpenAIAdapter) StreamInvokeTool(ctx context.Context, requestStream <-chan *ToolInvocationStreamChunk, responseStream chan<- *ToolInvocationStreamChunk) error {
	defer close(responseStream)

	// OpenAI handles tools through function calling in chat completion
	// Direct tool invocation is not supported by OpenAI API
	log.Printf("OpenAI does not support direct tool invocation - use function calling in chat completion")

	// Drain the request stream to prevent goroutine leaks
	go func() {
		for range requestStream {
			// Drain request stream
		}
	}()

	return fmt.Errorf("OpenAI adapter does not support direct tool invocation; use function calling within chat completion instead")
}

func (a *OpenAIAdapter) HealthCheck(ctx context.Context) error {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return fmt.Errorf("OpenAI adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if a.apiKey == "" {
		return fmt.Errorf("OpenAI API key is not configured for provider %s, health check skipped", a.name)
	}

	apiBase := a.cfg.LLMConfig.APIBase
	if apiBase == "" {
		apiBase = "https://api.openai.com/v1"
	}
	endpoint := apiBase + "/models"

	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create OpenAI HealthCheck HTTP request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	if a.cfg.LLMConfig.AzureAPIVersion != "" && a.cfg.LLMConfig.AzureAPIType == "azure" {
		httpReq.Header.Set("api-key", a.apiKey)
		httpReq.Header.Del("Authorization")
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("health check request to OpenAI API failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("OpenAI API health check failed with status %d: %s", httpResp.StatusCode, string(bodyBytes))
	}
	log.Printf("OpenAIAdapter: HealthCheck for provider %s successful.", a.name)
	return nil
}

func (a *OpenAIAdapter) Shutdown() error {
	a.shutdownMutex.Lock()
	defer a.shutdownMutex.Unlock()

	if a.isShutdown {
		log.Printf("OpenAIAdapter: Provider %s (ID: %s) is already shutdown", a.name, a.id)
		return nil
	}

	log.Printf("OpenAIAdapter: Initiating shutdown for provider %s (ID: %s)", a.name, a.id)

	// Clear sensitive data
	a.apiKey = ""

	// Mark as shutdown to prevent further operations
	a.isShutdown = true

	// Note: httpClient doesn't require explicit cleanup in Go as it will be garbage collected
	// The connection pool will be cleaned up when no references remain

	// Clear references to help with garbage collection
	a.secretManager = nil

	log.Printf("OpenAIAdapter: Shutdown completed for provider %s (ID: %s)", a.name, a.id)
	return nil
}
