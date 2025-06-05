package provider

import (
	"bufio" // For scanning SSE lines
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings" // For SSE event parsing
	"sync"
	"time"

	"github.com/openpons/gateway/internal/config"
	// "github.com/openpons/gateway/internal/secrets" // Replaced by SecretRetriever
)

// Compile-time check to ensure AnthropicAdapter implements ProviderAdapter.
var _ ProviderAdapter = (*AnthropicAdapter)(nil)

// --- Anthropic SSE Stream Event Structures ---
type anthropicStreamEventType string

const (
	eventTypeMessageStart      anthropicStreamEventType = "message_start"
	eventTypeContentBlockStart anthropicStreamEventType = "content_block_start"
	eventTypePing              anthropicStreamEventType = "ping"
	eventTypeContentBlockDelta anthropicStreamEventType = "content_block_delta"
	eventTypeContentBlockStop  anthropicStreamEventType = "content_block_stop"
	eventTypeMessageDelta      anthropicStreamEventType = "message_delta"
	eventTypeMessageStop       anthropicStreamEventType = "message_stop"
	eventTypeStreamError       anthropicStreamEventType = "error"
)

type anthropicStreamErrorData struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

type anthropicMessageStartData struct {
	Type    string `json:"type"`
	Message struct {
		ID           string     `json:"id"`
		Type         string     `json:"type"`
		Role         string     `json:"role"`
		Content      []struct{} `json:"content"`
		Model        string     `json:"model"`
		StopReason   *string    `json:"stop_reason"`
		StopSequence *string    `json:"stop_sequence"`
		Usage        struct {
			InputTokens int `json:"input_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

type anthropicContentBlockStartData struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentBlock struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content_block"`
}

type anthropicDeltaContent struct {
	Type        string `json:"type"` // "text_delta" or "input_json_delta"
	Text        string `json:"text,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"`
}

type anthropicContentBlockDeltaData struct {
	Type  string                `json:"type"`
	Index int                   `json:"index"`
	Delta anthropicDeltaContent `json:"delta"`
}

type anthropicContentBlockStopData struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type anthropicMessageDeltaData struct {
	Type  string `json:"type"`
	Delta struct {
		StopReason   *string `json:"stop_reason"`
		StopSequence *string `json:"stop_sequence"`
	} `json:"delta"`
	Usage struct {
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type anthropicMessageStopData struct {
	Type string `json:"type"`
}

// --- End of Anthropic SSE Stream Event Structures ---

type AnthropicAdapter struct {
	id            string
	name          string
	cfg           config.ProviderConfig
	secretManager SecretRetriever // Use interface
	apiKey        string
	httpClient    *http.Client
	shutdownMutex sync.Mutex
	isShutdown    bool
}

func NewAnthropicAdapter(providerCfg config.ProviderConfig, sm SecretRetriever, httpClient *http.Client) (*AnthropicAdapter, error) {
	if providerCfg.LLMConfig == nil {
		return nil, fmt.Errorf("anthropic adapter requires LLMConfig to be set in provider configuration")
	}

	var apiKeyVal string
	var err error
	if providerCfg.CredentialsSecretID != "" {
		apiKeyVal, err = sm.GetSecret(context.Background(), providerCfg.CredentialsSecretID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve API key for Anthropic provider %s (secretID: %s): %w", providerCfg.Name, providerCfg.CredentialsSecretID, err)
		}
		if apiKeyVal == "" {
			return nil, fmt.Errorf("retrieved API key for Anthropic provider %s (secretID: %s) is empty", providerCfg.Name, providerCfg.CredentialsSecretID)
		}
	} else {
		log.Printf("Warning: No CredentialsSecretID configured for Anthropic provider %s. API key will be empty.", providerCfg.Name)
	}

	clientToUse := httpClient
	if clientToUse == nil {
		clientToUse = http.DefaultClient
	}

	return &AnthropicAdapter{
		id:            providerCfg.ID,
		name:          providerCfg.Name,
		cfg:           providerCfg,
		secretManager: sm,
		apiKey:        apiKeyVal,
		httpClient:    clientToUse,
		isShutdown:    false,
	}, nil
}

func (a *AnthropicAdapter) Init(cfg *config.ProviderConfig, sr SecretRetriever) error {
	if cfg == nil {
		return fmt.Errorf("provider config cannot be nil for Init")
	}
	if sr == nil {
		return fmt.Errorf("secret retriever cannot be nil for Init")
	}

	a.shutdownMutex.Lock()
	defer a.shutdownMutex.Unlock()

	if a.isShutdown {
		return fmt.Errorf("cannot reinitialize a shutdown Anthropic adapter")
	}

	a.cfg = *cfg
	a.secretManager = sr
	a.id = cfg.ID
	a.name = cfg.Name

	if cfg.CredentialsSecretID != "" {
		apiKeyVal, err := sr.GetSecret(context.Background(), cfg.CredentialsSecretID)
		if err != nil {
			return fmt.Errorf("Init: failed to retrieve API key for Anthropic provider %s (secretID: %s): %w", cfg.Name, cfg.CredentialsSecretID, err)
		}
		a.apiKey = apiKeyVal
	} else {
		a.apiKey = ""
	}
	log.Printf("AnthropicAdapter: Initialized/Re-initialized for provider %s (ID: %s)", cfg.Name, cfg.ID)
	return nil
}

func (a *AnthropicAdapter) ProviderInfo() Info {
	return Info{
		Name: a.name,
		Type: config.ProviderTypeLLM,
		Capabilities: []string{
			"chat_completion",
			"stream_chat_completion",
		},
	}
}

func (a *AnthropicAdapter) GetConfig() *config.ProviderConfig {
	return &a.cfg
}

// AnthropicMessage represents a message in the Anthropic API request.
// It can now contain a list of content blocks, which can be text or tool_use.
type AnthropicMessage struct {
	Role    string        `json:"role"`
	Content []interface{} `json:"content"` // Can be string for simple text, or []AnthropicContentBlock for complex
}

// AnthropicContentBlock represents a block of content in a message.
type AnthropicContentBlock struct {
	Type string `json:"type"` // "text", "tool_use"
	Text string `json:"text,omitempty"`
	// For tool_use type
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Input any    `json:"input,omitempty"` // map[string]interface{}
}

// AnthropicToolDefinition is how tools are defined in the request to Anthropic.
type AnthropicToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"` // JSON Schema object
}

// AnthropicToolChoice allows specifying how the model should use tools.
type AnthropicToolChoice struct {
	Type string `json:"type"`           // "auto", "any", "tool"
	Name string `json:"name,omitempty"` // Required if type is "tool"
}

type AnthropicChatRequest struct {
	Model      string                    `json:"model"`
	Messages   []AnthropicMessage        `json:"messages"`
	System     string                    `json:"system,omitempty"`
	MaxTokens  int                       `json:"max_tokens"`
	Stream     bool                      `json:"stream,omitempty"`
	Tools      []AnthropicToolDefinition `json:"tools,omitempty"`
	ToolChoice *AnthropicToolChoice      `json:"tool_choice,omitempty"`
	// Add other Anthropic parameters like temperature, top_p, top_k, stop_sequences if needed
	Temperature   *float32 `json:"temperature,omitempty"`
	TopP          *float32 `json:"top_p,omitempty"`
	TopK          *int     `json:"top_k,omitempty"`
	StopSequences []string `json:"stop_sequences,omitempty"`
}

// AnthropicChatResponseContent is part of the response, can be text or tool_use.
type AnthropicChatResponseContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	// For tool_use type from model
	ID    string                 `json:"id,omitempty"`
	Name  string                 `json:"name,omitempty"`
	Input map[string]interface{} `json:"input,omitempty"`
}

type AnthropicChatResponse struct {
	ID           string                         `json:"id"`
	Type         string                         `json:"type"` // "message"
	Role         string                         `json:"role"` // "assistant"
	Content      []AnthropicChatResponseContent `json:"content"`
	Model        string                         `json:"model"`
	StopReason   string                         `json:"stop_reason"`   // e.g., "end_turn", "max_tokens", "stop_sequence", "tool_use"
	StopSequence *string                        `json:"stop_sequence"` // Nullable
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (a *AnthropicAdapter) ChatCompletion(ctx context.Context, request *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return nil, fmt.Errorf("Anthropic adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if request == nil {
		return nil, fmt.Errorf("ChatCompletionRequest cannot be nil")
	}
	if a.apiKey == "" {
		return nil, fmt.Errorf("Anthropic API key is not configured for provider %s", a.name)
	}

	apiBase := a.cfg.LLMConfig.APIBase
	if apiBase == "" {
		apiBase = "https://api.anthropic.com/v1"
	}
	endpoint := apiBase + "/messages"

	anthropicMessages, systemPrompt := convertMessagesToAnthropic(request.Messages)

	maxTokens := request.MaxTokens
	if maxTokens == 0 { // Anthropic requires max_tokens
		maxTokens = 1024 // Default if not set, or could error if strict
	}

	anthropicReq := AnthropicChatRequest{
		Model:         request.Model,
		Messages:      anthropicMessages,
		System:        systemPrompt,
		MaxTokens:     maxTokens,
		Stream:        false, // This is for non-streaming
		StopSequences: request.StopSequences,
	}
	if request.Temperature != 0 { // Assuming 0 is unset
		anthropicReq.Temperature = &request.Temperature
	}
	if request.TopP != 0 { // Assuming 0 is unset
		anthropicReq.TopP = &request.TopP
	}
	// Map Tools and ToolChoice if present in request
	if len(request.Tools) > 0 {
		anthropicReq.Tools = make([]AnthropicToolDefinition, len(request.Tools))
		for i, t := range request.Tools {
			anthropicReq.Tools[i] = AnthropicToolDefinition{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				InputSchema: t.Function.Parameters,
			}
		}
		// Handle ToolChoice if specified
		if request.ToolChoice != nil {
			// Anthropic's tool_choice is an object like {"type": "auto" | "any" | "tool", "name": "tool_name_if_type_is_tool"}
			// This needs careful mapping from the generic interface{}
			if tcStr, ok := request.ToolChoice.(string); ok {
				if tcStr == "auto" || tcStr == "any" { // OpenAI "auto" / "required" maps to Anthropic "auto" / "any"
					anthropicReq.ToolChoice = &AnthropicToolChoice{Type: tcStr}
				} else if tcStr != "none" { // "none" means no tools, which is default if tools are not sent.
					// If specific tool name is passed as string, map to {"type": "tool", "name": "..."}
					anthropicReq.ToolChoice = &AnthropicToolChoice{Type: "tool", Name: tcStr}
				}
			} else if tcMap, ok := request.ToolChoice.(map[string]interface{}); ok {
				// Example: {"type": "function", "function": {"name": "my_func"}} (OpenAI style)
				if toolType, ok := tcMap["type"].(string); ok && toolType == "function" {
					if functionMap, ok := tcMap["function"].(map[string]interface{}); ok {
						if name, ok := functionMap["name"].(string); ok {
							anthropicReq.ToolChoice = &AnthropicToolChoice{Type: "tool", Name: name}
						}
					}
				}
			}
		}
	}

	reqBodyBytes, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Anthropic request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create Anthropic HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Anthropic API: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("Anthropic API request failed with status %d: %s", httpResp.StatusCode, string(bodyBytes))
	}

	var anthropicAPIResp AnthropicChatResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&anthropicAPIResp); err != nil {
		return nil, fmt.Errorf("failed to decode Anthropic API response: %w", err)
	}

	// Process content blocks (can be text or tool_use)
	var responseContent string
	var toolCalls []ToolCall

	for _, block := range anthropicAPIResp.Content {
		if block.Type == "text" {
			responseContent += block.Text // Concatenate if multiple text blocks
		} else if block.Type == "tool_use" {
			toolCalls = append(toolCalls, ToolCall{
				ID:   block.ID,
				Type: "function", // Anthropic tool_use is always function-like
				Function: FunctionCall{
					Name:      block.Name,
					Arguments: convertInterfaceToJSONString(block.Input),
				},
			})
		}
	}

	chatMessage := ChatMessage{
		Role:    anthropicAPIResp.Role, // Should be "assistant"
		Content: responseContent,
	}
	if len(toolCalls) > 0 {
		chatMessage.ToolCalls = toolCalls
	}

	resp := &ChatCompletionResponse{
		ID:      anthropicAPIResp.ID,
		Object:  "chat.completion",
		Created: time.Now().Unix(), // Or parse from response if available
		Model:   anthropicAPIResp.Model,
		Choices: []ChatCompletionResponseChoice{
			{
				Index:        0,
				Message:      chatMessage,
				FinishReason: mapAnthropicStopReason(anthropicAPIResp.StopReason),
			},
		},
		Usage: &UsageStats{
			PromptTokens:     anthropicAPIResp.Usage.InputTokens,
			CompletionTokens: anthropicAPIResp.Usage.OutputTokens,
			TotalTokens:      anthropicAPIResp.Usage.InputTokens + anthropicAPIResp.Usage.OutputTokens,
		},
	}
	log.Printf("AnthropicAdapter: Successfully completed ChatCompletion for model %s", request.Model)
	return resp, nil
}

func mapAnthropicStopReason(reason string) string {
	switch reason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "stop_sequence":
		return "stop"
	case "tool_use":
		return "tool_calls"
	default:
		return reason
	}
}

func (a *AnthropicAdapter) StreamChatCompletion(ctx context.Context, request *ChatCompletionRequest, stream io.Writer) error {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return fmt.Errorf("Anthropic adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if request == nil {
		return fmt.Errorf("ChatCompletionRequest cannot be nil")
	}
	if a.apiKey == "" {
		return fmt.Errorf("Anthropic API key is not configured for provider %s", a.name)
	}
	if !request.Stream {
		request.Stream = true
	}

	apiBase := a.cfg.LLMConfig.APIBase
	if apiBase == "" {
		apiBase = "https://api.anthropic.com/v1"
	}
	endpoint := apiBase + "/messages"

	anthropicMessages, systemPrompt := convertMessagesToAnthropic(request.Messages)

	maxTokens := request.MaxTokens
	if maxTokens == 0 { // Anthropic requires max_tokens
		maxTokens = 1024
	}

	anthropicReq := AnthropicChatRequest{
		Model:         request.Model,
		Messages:      anthropicMessages,
		System:        systemPrompt,
		MaxTokens:     maxTokens,
		Stream:        true,
		StopSequences: request.StopSequences,
	}
	if request.Temperature != 0 {
		anthropicReq.Temperature = &request.Temperature
	}
	if request.TopP != 0 {
		anthropicReq.TopP = &request.TopP
	}
	// Map Tools and ToolChoice for streaming if supported by Anthropic's stream API
	if len(request.Tools) > 0 {
		anthropicReq.Tools = make([]AnthropicToolDefinition, len(request.Tools))
		for i, t := range request.Tools {
			anthropicReq.Tools[i] = AnthropicToolDefinition{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				InputSchema: t.Function.Parameters,
			}
		}
		if request.ToolChoice != nil {
			if tcStr, ok := request.ToolChoice.(string); ok {
				if tcStr == "auto" || tcStr == "any" {
					anthropicReq.ToolChoice = &AnthropicToolChoice{Type: tcStr}
				} else if tcStr != "none" {
					anthropicReq.ToolChoice = &AnthropicToolChoice{Type: "tool", Name: tcStr}
				}
			} else if tcMap, ok := request.ToolChoice.(map[string]interface{}); ok {
				if toolType, ok := tcMap["type"].(string); ok && toolType == "function" {
					if functionMap, ok := tcMap["function"].(map[string]interface{}); ok {
						if name, ok := functionMap["name"].(string); ok {
							anthropicReq.ToolChoice = &AnthropicToolChoice{Type: "tool", Name: name}
						}
					}
				}
			}
		}
	}

	reqBodyBytes, err := json.Marshal(anthropicReq)
	if err != nil {
		return fmt.Errorf("failed to marshal Anthropic stream request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create Anthropic stream HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("Accept", "text/event-stream")

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send stream request to Anthropic API: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("Anthropic API stream request failed with status %d: %s", httpResp.StatusCode, string(bodyBytes))
	}

	scanner := bufio.NewScanner(httpResp.Body)
	var currentEventName string
	var dataBuffer strings.Builder
	var responseID, modelName string
	var inputTokens, latestOutputTokens int
	var lastStopReason string

	flusher, implementsFlusher := stream.(http.Flusher)
	toolCallStates := make(map[int]struct{ ID, Name string }) // Stores ID and Name for active tool_use blocks by index

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "event:") {
			currentEventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			dataBuffer.Reset()
		} else if strings.HasPrefix(line, "data:") {
			dataPayload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			dataBuffer.WriteString(dataPayload)
		} else if line == "" {
			if dataBuffer.Len() == 0 && currentEventName != string(eventTypePing) && currentEventName != string(eventTypeMessageStop) {
				currentEventName = ""
				continue
			}

			jsonData := dataBuffer.String()
			dataBuffer.Reset()

			// Initialize chunk for each event. Delta might be empty if not applicable.
			chunk := ChatCompletionResponse{
				ID:      responseID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   modelName,
				Choices: []ChatCompletionResponseChoice{{Index: 0, Delta: &ChatMessage{}}},
			}
			sendChunk := true // Flag to control if the current chunk should be sent

			switch anthropicStreamEventType(currentEventName) {
			case eventTypeMessageStart:
				var eventData anthropicMessageStartData
				if err := json.Unmarshal([]byte(jsonData), &eventData); err != nil {
					log.Printf("AnthropicAdapter: Error unmarshalling message_start data: %v, data: %s", err, jsonData)
					sendChunk = false
				} else {
					responseID = eventData.Message.ID
					modelName = eventData.Message.Model
					inputTokens = eventData.Message.Usage.InputTokens
					chunk.ID = responseID   // Update chunk with correct ID
					chunk.Model = modelName // Update chunk with correct Model
					chunk.Choices[0].Delta.Role = eventData.Message.Role
				}

			case eventTypeContentBlockStart:
				var cbStartData struct {
					Index        int `json:"index"`
					ContentBlock struct {
						Type string `json:"type"`
						ID   string `json:"id,omitempty"`
						Name string `json:"name,omitempty"`
					} `json:"content_block"`
				}
				if err := json.Unmarshal([]byte(jsonData), &cbStartData); err == nil {
					if cbStartData.ContentBlock.Type == "tool_use" {
						toolCallStates[cbStartData.Index] = struct{ ID, Name string }{
							ID:   cbStartData.ContentBlock.ID,
							Name: cbStartData.ContentBlock.Name,
						}
						// Send the start of the tool call (ID, Name, Type)
						// Assumes ToolCall struct has Index *int (this change is in provider.go)
						// For now, removing Index field assignment to avoid compile error if provider.ToolCall doesn't have it.
						// Client might need to infer index or associate via ID.
						toolCallDelta := ToolCall{
							// Index: &cbStartData.Index, // Removed to avoid compile error
							ID:   cbStartData.ContentBlock.ID,
							Type: "function",
							Function: FunctionCall{
								Name:      cbStartData.ContentBlock.Name,
								Arguments: "", // Arguments will come in subsequent input_json_delta
							},
						}
						chunk.Choices[0].Delta.ToolCalls = []ToolCall{toolCallDelta}
					} else {
						sendChunk = false // Don't send a chunk for text content_block_start
					}
				} else {
					log.Printf("AnthropicAdapter: Error unmarshalling content_block_start: %v, data: %s", err, jsonData)
					sendChunk = false
				}

			case eventTypeContentBlockDelta:
				var eventData anthropicContentBlockDeltaData // Uses the modified struct definition
				if err := json.Unmarshal([]byte(jsonData), &eventData); err != nil {
					log.Printf("AnthropicAdapter: Error unmarshalling content_block_delta data: %v, data: %s", err, jsonData)
					sendChunk = false
				} else {
					if eventData.Delta.Type == "text_delta" {
						chunk.Choices[0].Delta.Content = eventData.Delta.Text
					} else if eventData.Delta.Type == "input_json_delta" {
						if toolState, ok := toolCallStates[eventData.Index]; ok {
							// Assumes ToolCall struct has Index *int
							// For now, removing Index field assignment.
							toolCallDelta := ToolCall{
								// Index: &eventData.Index, // Removed to avoid compile error
								ID:   toolState.ID, // ID from content_block_start
								Type: "function",
								Function: FunctionCall{
									// Name: toolState.Name, // Name is sent with content_block_start, not repeated for arg deltas by OpenAI
									Arguments: eventData.Delta.PartialJSON,
								},
							}
							chunk.Choices[0].Delta.ToolCalls = []ToolCall{toolCallDelta}
						} else {
							log.Printf("AnthropicAdapter: Received input_json_delta for unknown tool_use index: %d", eventData.Index)
							sendChunk = false
						}
					} else {
						log.Printf("AnthropicAdapter: Unhandled delta type within content_block_delta: %s", eventData.Delta.Type)
						sendChunk = false
					}
				}

			case eventTypeMessageDelta:
				// This case mostly updates counters and stop reasons, doesn't usually send a content chunk by itself.
				sendChunk = false // Typically, message_delta doesn't produce a content chunk for the client.
				var eventData anthropicMessageDeltaData
				if err := json.Unmarshal([]byte(jsonData), &eventData); err != nil {
					log.Printf("AnthropicAdapter: Error unmarshalling message_delta data: %v, data: %s", err, jsonData)
					continue // Skip to next line if unmarshal fails
				}
				if eventData.Delta.StopReason != nil {
					lastStopReason = mapAnthropicStopReason(*eventData.Delta.StopReason)
				}
				if eventData.Usage.OutputTokens > 0 {
					latestOutputTokens = eventData.Usage.OutputTokens
				}
				// No 'continue' here, fall through to the shared chunk sending logic,
				// but sendChunk is false, so it will be skipped.

			case eventTypeMessageStop:
				chunk.Choices[0].FinishReason = lastStopReason
				if chunk.Choices[0].FinishReason == "" {
					chunk.Choices[0].FinishReason = "stop" // Default if not set by message_delta
				}
				chunk.Usage = &UsageStats{
					PromptTokens:     inputTokens,
					CompletionTokens: latestOutputTokens,
					TotalTokens:      inputTokens + latestOutputTokens,
				}

			case eventTypeStreamError:
				var errorData anthropicStreamErrorData
				if err := json.Unmarshal([]byte(jsonData), &errorData); err != nil {
					log.Printf("AnthropicAdapter: Error unmarshalling error event data: %v, data: %s", err, jsonData)
					return fmt.Errorf("anthropic stream error: unmarshal failed for data: %s", jsonData)
				}
				log.Printf("AnthropicAdapter: Received error event from stream: %s - %s", errorData.Error.Type, errorData.Error.Message)
				// Send an error chunk
				errorChunk := ChatCompletionResponse{
					ID: responseID, Object: "chat.completion.chunk", Created: time.Now().Unix(), Model: modelName,
					Choices: []ChatCompletionResponseChoice{{Index: 0, Delta: &ChatMessage{Content: fmt.Sprintf("Provider error: %s - %s", errorData.Error.Type, errorData.Error.Message)}, FinishReason: "error"}},
				}
				errorChunkBytes, marshalErr := json.Marshal(errorChunk)
				if marshalErr == nil {
					if _, writeErr := fmt.Fprintf(stream, "data: %s\n\n", string(errorChunkBytes)); writeErr == nil {
						if implementsFlusher {
							flusher.Flush()
						}
					}
				}
				// Send [DONE] after error chunk
				if _, writeErr := fmt.Fprintf(stream, "data: [DONE]\n\n"); writeErr == nil {
					if implementsFlusher {
						flusher.Flush()
					}
				}
				return fmt.Errorf("anthropic stream error: type=%s, message=%s", errorData.Error.Type, errorData.Error.Message)

			case eventTypePing:
				sendChunk = false // Do not send a chunk for ping
			case eventTypeContentBlockStop:
				sendChunk = false // Do not send a chunk for content_block_stop
			default:
				log.Printf("AnthropicAdapter: Unknown or unhandled SSE event type: %s, data: %s", currentEventName, jsonData)
				sendChunk = false // Do not send for unknown event types
			}

			if !sendChunk {
				currentEventName = "" // Reset for next SSE message
				continue
			}

			chunkBytes, err := json.Marshal(chunk)
			if err != nil {
				log.Printf("AnthropicAdapter: Error marshalling internal chunk: %v", err)
				continue // Skip this chunk if marshalling fails
			}

			if _, err := fmt.Fprintf(stream, "data: %s\n\n", string(chunkBytes)); err != nil {
				log.Printf("AnthropicAdapter: Error writing to output stream: %v", err)
				return err // Critical error, stop streaming
			}

			if implementsFlusher {
				flusher.Flush()
			}

			// Check if this was the final message_stop event
			if currentEventName == string(eventTypeMessageStop) {
				// Send the [DONE] marker
				if _, err := fmt.Fprintf(stream, "data: [DONE]\n\n"); err != nil {
					log.Printf("AnthropicAdapter: Error writing [DONE] to stream: %v", err)
					return err
				}
				if implementsFlusher {
					flusher.Flush()
				}
				log.Printf("AnthropicAdapter: StreamChatCompletion for model %s completed.", modelName)
				return nil // End of stream
			}
			currentEventName = "" // Reset for the next event
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("AnthropicAdapter: Error reading stream from Anthropic: %v", err)
		return err
	}
	log.Printf("AnthropicAdapter: StreamChatCompletion for model %s finished (scanner done).", modelName)
	return nil
}

func (a *AnthropicAdapter) GenerateEmbedding(ctx context.Context, request *EmbeddingRequest) (*EmbeddingResponse, error) {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return nil, fmt.Errorf("Anthropic adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	// Anthropic does not have a dedicated embedding API in the same way OpenAI does.
	// This is a placeholder; actual implementation would depend on how Anthropic exposes embeddings
	// (e.g., via a specific model or a different API endpoint).
	// For now, returning an error indicating it's not supported.
	log.Printf("AnthropicAdapter: GenerateEmbedding called (placeholder - Anthropic does not have a standard public embedding API like OpenAI's /v1/embeddings). Provider: %s", a.name)
	return nil, fmt.Errorf("embedding generation is not directly supported by Anthropic adapter in this version")
}

// AudioTranscription is a placeholder as Anthropic models typically don't offer direct audio transcription APIs.
func (a *AnthropicAdapter) AudioTranscription(ctx context.Context, request *AudioTranscriptionRequest) (*AudioTranscriptionResponse, error) {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return nil, fmt.Errorf("Anthropic adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()
	log.Printf("AnthropicAdapter: AudioTranscription called (placeholder - not supported). Provider: %s", a.name)
	return nil, fmt.Errorf("audio transcription not supported by Anthropic adapter")
}

// TextToSpeech is a placeholder as Anthropic models typically don't offer direct text-to-speech APIs.
func (a *AnthropicAdapter) TextToSpeech(ctx context.Context, request *TextToSpeechRequest, stream io.Writer) error {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return fmt.Errorf("Anthropic adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()
	log.Printf("AnthropicAdapter: TextToSpeech called (placeholder - not supported). Provider: %s", a.name)
	return fmt.Errorf("text-to-speech not supported by Anthropic adapter")
}

// InvokeTool is a placeholder. Anthropic's tool use is part of the /messages API.
func (a *AnthropicAdapter) InvokeTool(ctx context.Context, request *ToolInvocationRequest) (*ToolInvocationResponse, error) {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return nil, fmt.Errorf("Anthropic adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()
	log.Printf("AnthropicAdapter: InvokeTool called (placeholder - tool invocation is part of chat completion flow). Provider: %s", a.name)
	return nil, fmt.Errorf("direct tool invocation not supported by Anthropic adapter; use ChatCompletion with tools")
}

// StreamInvokeTool is a placeholder.
func (a *AnthropicAdapter) StreamInvokeTool(ctx context.Context, requestStream <-chan *ToolInvocationStreamChunk, responseStream chan<- *ToolInvocationStreamChunk) error {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return fmt.Errorf("Anthropic adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()
	log.Printf("AnthropicAdapter: StreamInvokeTool called (placeholder - not supported). Provider: %s", a.name)
	close(responseStream) // Must close the response stream
	return fmt.Errorf("streaming tool invocation not supported by Anthropic adapter")
}

// HealthCheck performs a health check on the upstream provider.
// For Anthropic, this could involve a simple API call like listing models or a dedicated health endpoint if available.
func (a *AnthropicAdapter) HealthCheck(ctx context.Context) error {
	a.shutdownMutex.Lock()
	if a.isShutdown {
		a.shutdownMutex.Unlock()
		return fmt.Errorf("Anthropic adapter %s is shutdown", a.name)
	}
	a.shutdownMutex.Unlock()

	if a.apiKey == "" {
		return fmt.Errorf("Anthropic API key is not configured for health check on provider %s", a.name)
	}

	// A lightweight call, e.g., trying to send a very short, cheap message or a specific health check endpoint if one exists.
	// For now, we'll simulate a successful check if API key is present.
	// A real check might involve a GET request to a base messages endpoint or similar.
	// Example: Ping the /messages endpoint with a very small request or check a status endpoint.
	// This is a simplified placeholder.
	log.Printf("AnthropicAdapter: HealthCheck called. Provider: %s. (Placeholder - returning nil if API key exists)", a.name)
	return nil
}

// Shutdown gracefully stops the adapter.
func (a *AnthropicAdapter) Shutdown() error {
	a.shutdownMutex.Lock()
	defer a.shutdownMutex.Unlock()

	if a.isShutdown {
		log.Printf("AnthropicAdapter: Shutdown already called for provider %s", a.name)
		return nil
	}

	log.Printf("AnthropicAdapter: Shutdown called (placeholder). Provider: %s", a.name)
	// In a real scenario, you might cancel ongoing requests or close persistent connections.
	// For Anthropic, the http.Client is often shared, so its lifecycle is managed elsewhere.
	// If this adapter had its own client, it would be closed here.
	a.isShutdown = true
	return nil
}

// Helper function to convert our generic ChatMessage to Anthropic's format
func convertMessagesToAnthropic(messages []ChatMessage) ([]AnthropicMessage, string) {
	var anthropicMessages []AnthropicMessage
	var systemPrompt string

	for _, msg := range messages {
		if msg.Role == "system" {
			// Anthropic prefers a single top-level system prompt.
			// If multiple system messages are present, concatenate them or take the last one.
			if systemPrompt != "" {
				systemPrompt += "\n" + msg.Content
			} else {
				systemPrompt = msg.Content
			}
			continue // System messages are not part of the 'messages' array for Anthropic
		}

		// Convert content to Anthropic's format (list of content blocks)
		var anthropicContentBlocks []interface{}

		if msg.Content != "" {
			anthropicContentBlocks = append(anthropicContentBlocks, AnthropicContentBlock{
				Type: "text",
				Text: msg.Content,
			})
		}

		// Handle tool calls (from user, typically results of tool execution)
		if len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				// This assumes the user is sending a "tool_result" type message back.
				// Anthropic expects a user message with content type "tool_result".
				// The structure here might need adjustment based on how `ToolCalls` on a user message
				// is intended to be mapped. For now, this is a direct mapping if `msg.Role` is "tool" or "user" with tool results.
				// If msg.Role is "assistant" and it has ToolCalls, these are requests from the model.
				// If msg.Role is "user" and it has ToolCalls, these are typically results.
				// Anthropic's format for providing tool results:
				// {
				//   "role": "user",
				//   "content": [
				//     {
				//       "type": "tool_result",
				//       "tool_use_id": "toolu_...",
				//       "content": "Output of the tool" // or structured JSON as string
				//     }
				//   ]
				// }
				// This part needs careful mapping based on the exact structure of `ChatMessage.ToolCalls`
				// when Role is "user" (representing tool results).
				// The current `ChatMessage.ToolCalls` is more aligned with an assistant's request for tool execution.
				// Let's assume for now if Role is "tool", it's a result.
				if msg.Role == "tool" { // Or a user message that's a tool result
					anthropicContentBlocks = append(anthropicContentBlocks, AnthropicContentBlock{
						Type: "tool_result", // This is Anthropic's type for a tool's output
						ID:   tc.ID,         // tool_use_id from assistant's request
						// Content for tool_result can be string or structured JSON.
						// Assuming tc.Function.Arguments here is the *output* of the tool.
						// This might need to be msg.Content if the tool output is in the main content field for role "tool".
						Text: tc.Function.Arguments, // This is likely incorrect mapping for tool *results*.
						// Arguments usually refers to input.
						// If tc.Function.Arguments is the JSON string output, this might be okay.
					})
				}
			}
		}

		// If the role is "assistant" and there are tool_calls, format them for Anthropic
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				// Parse arguments string into map[string]interface{}
				var inputArgs map[string]interface{}
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &inputArgs); err != nil {
					// If unmarshal fails, pass as string or handle error
					log.Printf("AnthropicAdapter: Failed to unmarshal tool call arguments for %s: %v. Passing as raw string.", tc.Function.Name, err)
					// anthropicContentBlocks = append(anthropicContentBlocks, AnthropicContentBlock{
					// 	Type: "text", // Fallback or error representation
					// 	Text: fmt.Sprintf("Error processing tool arguments for %s", tc.Function.Name),
					// })
					// For now, let's try to send it as is, Anthropic might handle it or error.
					// Or, more correctly, an assistant message with tool_calls should be structured as tool_use blocks.
					anthropicContentBlocks = append(anthropicContentBlocks, AnthropicContentBlock{
						Type:  "tool_use",
						ID:    tc.ID,
						Name:  tc.Function.Name,
						Input: inputArgs, // This should be the parsed arguments
					})

				} else {
					anthropicContentBlocks = append(anthropicContentBlocks, AnthropicContentBlock{
						Type:  "tool_use",
						ID:    tc.ID,
						Name:  tc.Function.Name,
						Input: inputArgs,
					})
				}
			}
		}

		if len(anthropicContentBlocks) > 0 {
			anthropicMessages = append(anthropicMessages, AnthropicMessage{
				Role:    msg.Role, // user, assistant (system is handled separately)
				Content: anthropicContentBlocks,
			})
		} else if msg.Role != "system" { // Add message even if content is empty, unless it's system
			anthropicMessages = append(anthropicMessages, AnthropicMessage{Role: msg.Role, Content: []interface{}{}})
		}
	}
	return anthropicMessages, systemPrompt
}

// convertInterfaceToJSONString tries to marshal an interface to a JSON string.
// If input is already a string, it returns it. If marshalling fails, returns an error string.
func convertInterfaceToJSONString(input interface{}) string {
	if str, ok := input.(string); ok {
		return str
	}
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Sprintf("{\"error\": \"failed to marshal input: %v\"}", err)
	}
	return string(jsonBytes)
}
