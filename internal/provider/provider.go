// Package provider contains adapters for various upstream AI service providers
// (LLMs, MCP tool servers, A2A agents). It abstracts provider-specific APIs
// behind common interfaces.
package provider

import (
	"context"
	"encoding/json"
	"io"

	"github.com/openpons/gateway/internal/config" // For ProviderConfig
	// No direct import of secrets here, define an interface for what provider package needs
)

// SecretRetriever defines the interface for retrieving secrets, to be implemented
// by the actual secrets.SecretManager. This decouples provider package from secrets package.
type SecretRetriever interface {
	GetSecret(ctx context.Context, id string) (string, error)
}

// Internal, simplified request/response structs, often OpenAI-like for consistency.
// These are what the gateway uses internally; adapters translate to/from provider-specific formats.

// ChatMessage mirrors a generic chat message structure.
type ChatMessage struct {
	Role       string     `json:"role"` // system, user, assistant, tool
	Content    string     `json:"content"`
	Name       string     `json:"name,omitempty"`         // For tool role or function name
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`   // For assistant messages requesting tool use
	ToolCallID string     `json:"tool_call_id,omitempty"` // For tool role messages
}

// FunctionDefinition describes a function available to the model.
type FunctionDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"` // JSON Schema object
}

// Tool represents a tool definition that can be passed to the model.
type Tool struct {
	Type     string             `json:"type"` // e.g., "function"
	Function FunctionDefinition `json:"function"`
}

// FunctionCall represents the function call requested by the model.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string of arguments
}

// ToolCall represents a tool call requested by the model.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // Currently, only "function" is supported by OpenAI
	Function FunctionCall `json:"function"`
}

// ChatCompletionRequest is an internal representation for a chat completion request.
type ChatCompletionRequest struct {
	Model            string        `json:"model"` // The specific model ID requested by the user via a route
	Messages         []ChatMessage `json:"messages"`
	MaxTokens        int           `json:"max_tokens,omitempty"`
	Temperature      float32       `json:"temperature,omitempty"`
	TopP             float32       `json:"top_p,omitempty"`
	Stream           bool          `json:"stream,omitempty"`
	StopSequences    []string      `json:"stop,omitempty"`
	PresencePenalty  float32       `json:"presence_penalty,omitempty"`
	FrequencyPenalty float32       `json:"frequency_penalty,omitempty"`
	Tools            []Tool        `json:"tools,omitempty"`
	ToolChoice       interface{}   `json:"tool_choice,omitempty"` // string or object (e.g., {"type": "function", "function": {"name": "my_function"}})
	User             string        `json:"user,omitempty"`        // End-user identifier
	// SessionID for stateful interactions if needed by provider or plugins
	SessionID string `json:"-"` // Internal, not part of OpenAI spec directly
}

// ChatCompletionResponseChoice is part of the response.
type ChatCompletionResponseChoice struct {
	Index        int          `json:"index"`
	Message      ChatMessage  `json:"message"`
	Delta        *ChatMessage `json:"delta,omitempty"`         // For streaming
	FinishReason string       `json:"finish_reason,omitempty"` // e.g., "stop", "length", "tool_calls"
}

// UsageStats represents token usage for a completion.
type UsageStats struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatCompletionResponse is an internal representation for a chat completion response.
type ChatCompletionResponse struct {
	ID                string                         `json:"id"`      // Unique ID for the completion
	Object            string                         `json:"object"`  // "chat.completion" or "chat.completion.chunk"
	Created           int64                          `json:"created"` // Unix timestamp
	Model             string                         `json:"model"`   // Model used for the completion
	Choices           []ChatCompletionResponseChoice `json:"choices"`
	Usage             *UsageStats                    `json:"usage,omitempty"`
	SystemFingerprint string                         `json:"system_fingerprint,omitempty"`
}

// EmbeddingRequest is an internal representation for an embedding request.
type EmbeddingRequest struct {
	Model string      `json:"model"`
	Input interface{} `json:"input"` // string or []string or [][]int
	User  string      `json:"user,omitempty"`
}

// Embedding represents a single embedding vector.
type Embedding struct {
	Object    string    `json:"object"` // "embedding"
	Embedding []float32 `json:"embedding"`
	Index     int       `json:"index"`
}

// EmbeddingResponse is an internal representation for an embedding response.
type EmbeddingResponse struct {
	Object string      `json:"object"` // "list"
	Data   []Embedding `json:"data"`
	Model  string      `json:"model"`
	Usage  UsageStats  `json:"usage"`
}

// ToolInvocationRequest for MCP/A2A style tool calls.
type ToolInvocationRequest struct {
	ToolName  string                 `json:"tool_name"`
	Arguments map[string]interface{} `json:"arguments"`
	SessionID string                 `json:"session_id,omitempty"` // For stateful tools
	// User context, etc.
}

// ToolInvocationResponse for MCP/A2A style tool calls.
type ToolInvocationResponse struct {
	Result    interface{} `json:"result"` // Can be complex object
	Error     *ToolError  `json:"error,omitempty"`
	SessionID string      `json:"session_id,omitempty"`
	// Logs, stdout, etc.
}
type ToolError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// ToolInvocationStreamChunk represents a chunk in a streaming tool invocation.
// This is a generic structure; specific protocols (MCP, A2A) might have more detailed chunk types.
type ToolInvocationStreamChunk struct {
	Payload   []byte                 `json:"payload,omitempty"`    // Raw payload for the chunk
	Error     *ToolError             `json:"error,omitempty"`      // If this chunk represents an error
	IsLast    bool                   `json:"is_last,omitempty"`    // Indicates if this is the last chunk in its direction
	Metadata  map[string]interface{} `json:"metadata,omitempty"`   // Any other metadata
	SessionID string                 `json:"session_id,omitempty"` // Could be part of initial chunk or metadata
}

// --- Audio Types ---

// AudioTranscriptionRequest mirrors OpenAI's transcription request.
type AudioTranscriptionRequest struct {
	File           io.Reader `json:"-"` // Reader for audio file data, not part of JSON
	FileName       string    `json:"-"` // Original file name, for content type detection
	Model          string    `json:"model"`
	Language       string    `json:"language,omitempty"`        // ISO-639-1 language code
	Prompt         string    `json:"prompt,omitempty"`          // Optional context prompt
	ResponseFormat string    `json:"response_format,omitempty"` // e.g., "json", "text", "srt", "verbose_json", "vtt"
	Temperature    float32   `json:"temperature,omitempty"`
}

// AudioTranscriptionResponse mirrors OpenAI's transcription response (for format="json" or "verbose_json").
type AudioTranscriptionResponse struct {
	Text     string    `json:"text"`               // For simple text response
	Task     string    `json:"task,omitempty"`     // e.g., "transcribe"
	Language string    `json:"language,omitempty"` // Detected language
	Duration float64   `json:"duration,omitempty"` // Duration of the audio in seconds
	Segments []Segment `json:"segments,omitempty"` // For verbose_json
}

// Segment is part of AudioTranscriptionResponse for verbose formats.
type Segment struct {
	ID               int     `json:"id"`
	Seek             int     `json:"seek"`
	Start            float64 `json:"start"` // Start time in seconds
	End              float64 `json:"end"`   // End time in seconds
	Text             string  `json:"text"`
	Tokens           []int   `json:"tokens"`
	Temperature      float32 `json:"temperature"`
	AvgLogprob       float64 `json:"avg_logprob"`
	CompressionRatio float64 `json:"compression_ratio"`
	NoSpeechProb     float64 `json:"no_speech_prob"`
}

// TextToSpeechRequest mirrors OpenAI's TTS request.
type TextToSpeechRequest struct {
	Model          string  `json:"model"`                     // e.g., "tts-1", "tts-1-hd"
	Input          string  `json:"input"`                     // Text to synthesize
	Voice          string  `json:"voice"`                     // e.g., "alloy", "echo", "fable", "onyx", "nova", "shimmer"
	ResponseFormat string  `json:"response_format,omitempty"` // e.g., "mp3", "opus", "aac", "flac" (default "mp3")
	Speed          float32 `json:"speed,omitempty"`           // 0.25 to 4.0 (default 1.0)
}

// TextToSpeechResponse contains the audio data.
// The actual audio data will be streamed or returned as bytes, not in this struct directly.
// This struct could hold metadata if the API returns any.
type TextToSpeechResponse struct {
	AudioData   []byte `json:"-"` // The raw audio bytes
	ContentType string `json:"-"` // e.g., "audio/mpeg" for mp3
}

// ProviderAdapter defines the common interface for interacting with various AI service providers.
// It includes methods for initialization, info retrieval, and specific AI operations.
type ProviderAdapter interface {
	// Init initializes the adapter with its configuration and a secret retriever.
	Init(cfg *config.ProviderConfig, sr SecretRetriever) error

	// ProviderInfo returns static information about the provider adapter.
	ProviderInfo() Info // Renamed from GetName, GetType for a struct return

	// GetConfig returns the configuration used by this adapter.
	GetConfig() *config.ProviderConfig // Return pointer for consistency

	// LLM specific methods
	ChatCompletion(ctx context.Context, request *ChatCompletionRequest) (*ChatCompletionResponse, error)             // Use pointers
	StreamChatCompletion(ctx context.Context, request *ChatCompletionRequest, stream io.Writer) error                // Use pointers
	GenerateEmbedding(ctx context.Context, request *EmbeddingRequest) (*EmbeddingResponse, error)                    // Use pointers
	AudioTranscription(ctx context.Context, request *AudioTranscriptionRequest) (*AudioTranscriptionResponse, error) // Use pointers
	TextToSpeech(ctx context.Context, request *TextToSpeechRequest, stream io.Writer) error                          // Use pointers

	// Tool/Agent specific methods (MCP, A2A)
	InvokeTool(ctx context.Context, request *ToolInvocationRequest) (*ToolInvocationResponse, error)                                               // Use pointers
	StreamInvokeTool(ctx context.Context, requestStream <-chan *ToolInvocationStreamChunk, responseStream chan<- *ToolInvocationStreamChunk) error // Use pointers

	// HealthCheck performs a health check on the upstream provider.
	HealthCheck(ctx context.Context) error

	// Shutdown cleans up any resources used by the adapter.
	Shutdown() error // Renamed from Close for consistency
}

// Info holds static information about a provider adapter.
type Info struct {
	Name         string              // User-friendly name, e.g., "openai-gpt4"
	Type         config.ProviderType // llm, tool_server, agent_platform
	Capabilities []string            // e.g., ["chat", "embeddings", "tts"]
}
