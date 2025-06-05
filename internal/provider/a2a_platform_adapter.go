package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings" // For joining paths
	"time"    // For HealthCheck timeout

	"github.com/gorilla/websocket"
	"github.com/openpons/gateway/internal/config"
	// "github.com/openpons/gateway/internal/secrets" // Will be replaced by SecretRetriever interface
)

var _ ProviderAdapter = (*A2APlatformAdapter)(nil)

type A2APlatformAdapter struct {
	id            string
	name          string
	cfg           config.ProviderConfig
	secretManager SecretRetriever // Use interface
	httpClient    *http.Client
	apiKey        string // Store API key if configured
}

func NewA2APlatformAdapter(providerCfg config.ProviderConfig, sm SecretRetriever, httpClient *http.Client) (*A2APlatformAdapter, error) {
	if providerCfg.A2APlatformConfig == nil {
		return nil, fmt.Errorf("A2APlatformAdapter requires A2APlatformConfig to be set")
	}
	log.Printf("A2APlatformAdapter: Initializing for provider %s (ID: %s), hub: %s", providerCfg.Name, providerCfg.ID, providerCfg.A2APlatformConfig.HubAddress)

	var apiKeyVal string
	var err error
	if providerCfg.CredentialsSecretID != "" {
		// Use a background context for initialization phase secret fetching.
		// Production systems might need a more sophisticated context management here.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		apiKeyVal, err = sm.GetSecret(ctx, providerCfg.CredentialsSecretID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve API key for A2A provider %s (secretID: %s): %w", providerCfg.Name, providerCfg.CredentialsSecretID, err)
		}
		if apiKeyVal == "" {
			log.Printf("Warning: Retrieved API key for A2A provider %s (secretID: %s) is empty.", providerCfg.Name, providerCfg.CredentialsSecretID)
			// Depending on policy, this could be an error.
		}
	} else {
		log.Printf("Info: No CredentialsSecretID configured for A2A provider %s. Assuming no API key needed or handled by httpClient.", providerCfg.Name)
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second} // Default client if none provided
	}

	return &A2APlatformAdapter{
		id:            providerCfg.ID,
		name:          providerCfg.Name,
		cfg:           providerCfg,
		secretManager: sm,
		httpClient:    httpClient,
		apiKey:        apiKeyVal,
	}, nil
}

// Init initializes the adapter.
func (a *A2APlatformAdapter) Init(cfg *config.ProviderConfig, sr SecretRetriever) error {
	if cfg == nil {
		return fmt.Errorf("provider config cannot be nil for Init")
	}
	if sr == nil {
		return fmt.Errorf("secret retriever cannot be nil for Init")
	}
	a.cfg = *cfg
	a.secretManager = sr
	a.id = cfg.ID
	a.name = cfg.Name

	if cfg.CredentialsSecretID != "" {
		apiKeyVal, err := sr.GetSecret(context.Background(), cfg.CredentialsSecretID)
		if err != nil {
			return fmt.Errorf("Init: failed to retrieve API key for A2A provider %s (secretID: %s): %w", cfg.Name, cfg.CredentialsSecretID, err)
		}
		a.apiKey = apiKeyVal
	} else {
		a.apiKey = ""
	}
	if cfg.A2APlatformConfig == nil {
		// Ensure A2APlatformConfig is initialized if cfg was updated
		a.cfg.A2APlatformConfig = &config.A2APlatformConfig{}
	}
	log.Printf("A2APlatformAdapter: Initialized/Re-initialized for provider %s (ID: %s)", cfg.Name, cfg.ID)
	return nil
}

func (a *A2APlatformAdapter) ProviderInfo() Info {
	return Info{
		Name: a.name,
		Type: config.ProviderTypeAgentPlatform,
		Capabilities: []string{
			"invoke_tool",
			// "stream_invoke_tool", // Add if/when implemented
		},
	}
}

func (a *A2APlatformAdapter) GetConfig() *config.ProviderConfig { return &a.cfg }

func (a *A2APlatformAdapter) ChatCompletion(ctx context.Context, request *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	return nil, fmt.Errorf("ChatCompletion not supported by A2APlatformAdapter")
}

func (a *A2APlatformAdapter) StreamChatCompletion(ctx context.Context, request *ChatCompletionRequest, stream io.Writer) error {
	return fmt.Errorf("StreamChatCompletion not supported by A2APlatformAdapter")
}

func (a *A2APlatformAdapter) GenerateEmbedding(ctx context.Context, request *EmbeddingRequest) (*EmbeddingResponse, error) {
	return nil, fmt.Errorf("GenerateEmbedding not supported by A2APlatformAdapter")
}

func (a *A2APlatformAdapter) AudioTranscription(ctx context.Context, request *AudioTranscriptionRequest) (*AudioTranscriptionResponse, error) {
	return nil, fmt.Errorf("AudioTranscription not supported by A2APlatformAdapter")
}

func (a *A2APlatformAdapter) TextToSpeech(ctx context.Context, request *TextToSpeechRequest, stream io.Writer) error {
	return fmt.Errorf("TextToSpeech not supported by A2APlatformAdapter")
}

func (a *A2APlatformAdapter) InvokeTool(ctx context.Context, request *ToolInvocationRequest) (*ToolInvocationResponse, error) {
	if a.cfg.A2APlatformConfig.HubAddress == "" {
		return nil, fmt.Errorf("A2A HubAddress is not configured for provider %s", a.name)
	}

	// Assuming a RESTful endpoint like: {HubAddress}/invoke/{taskName}
	// ToolName in request is used as the task name.
	endpoint := strings.TrimRight(a.cfg.A2APlatformConfig.HubAddress, "/") + "/invoke/" + request.ToolName
	log.Printf("A2APlatformAdapter: Invoking tool/task '%s' at endpoint '%s'", request.ToolName, endpoint)

	reqBodyBytes, err := json.Marshal(request.Arguments)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal A2A request arguments for task %s: %w", request.ToolName, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create A2A HTTP request for task %s: %w", request.ToolName, err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.apiKey) // Or other scheme as needed
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to A2A platform for task %s: %w", request.ToolName, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		// Attempt to parse for a ToolError if the A2A platform returns structured errors
		var toolErr ToolError
		if json.Unmarshal(bodyBytes, &toolErr) == nil && toolErr.Message != "" {
			return &ToolInvocationResponse{Error: &toolErr}, nil
		}
		return nil, fmt.Errorf("A2A platform request for task %s failed with status %d: %s", request.ToolName, httpResp.StatusCode, string(bodyBytes))
	}

	var toolResp ToolInvocationResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&toolResp); err != nil {
		// If decoding into ToolInvocationResponse fails, but we got a 200,
		// it might be that the A2A platform returns the raw result directly.
		// For simplicity, let's try to read the body as raw JSON if the above fails.
		// This part needs to align with the actual A2A platform's response contract.
		// Rewind or re-read body if necessary and possible (not straightforward with http.Response.Body)
		// For now, assume direct decoding or error.
		// A more robust solution would involve reading body once, then trying to unmarshal.
		log.Printf("A2APlatformAdapter: Successfully invoked task %s, but failed to decode response into ToolInvocationResponse struct: %v. Returning raw body if possible or error.", request.ToolName, err)
		// This is tricky. If the response was a simple JSON value (string, number, bool) not fitting ToolInvocationResponse,
		// we might want to capture it. For now, we'll stick to the defined struct or error.
		// A common pattern is for the platform to always return a structure like ToolInvocationResponse.
		return nil, fmt.Errorf("failed to decode A2A platform response for task %s: %w", request.ToolName, err)

	}

	log.Printf("A2APlatformAdapter: Successfully invoked task %s", request.ToolName)
	return &toolResp, nil
}

func (a *A2APlatformAdapter) StreamInvokeTool(ctx context.Context, requestStream <-chan *ToolInvocationStreamChunk, responseStream chan<- *ToolInvocationStreamChunk) error {
	defer close(responseStream)

	if a.cfg.A2APlatformConfig.HubAddress == "" {
		return fmt.Errorf("A2A HubAddress not configured for streaming for provider %s", a.name)
	}

	// Convert HTTP URL to WebSocket URL for streaming
	wsURL := strings.Replace(a.cfg.A2APlatformConfig.HubAddress, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.TrimRight(wsURL, "/") + "/stream"

	log.Printf("A2APlatformAdapter: Establishing WebSocket connection to %s", wsURL)

	// Create WebSocket dialer with headers
	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	headers := http.Header{}
	if a.apiKey != "" {
		headers.Set("Authorization", "Bearer "+a.apiKey)
	}

	// Establish WebSocket connection
	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return fmt.Errorf("failed to connect to A2A platform WebSocket: %w", err)
	}
	defer conn.Close()

	log.Printf("A2APlatformAdapter: WebSocket connection established for streaming")

	// Handle bidirectional streaming
	errChan := make(chan error, 2)

	// Goroutine to send requests
	go func() {
		defer func() {
			// Send close message to indicate no more requests
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		}()

		for chunk := range requestStream {
			if err := conn.WriteJSON(chunk); err != nil {
				errChan <- fmt.Errorf("failed to send chunk to A2A platform: %w", err)
				return
			}
		}
		errChan <- nil
	}()

	// Goroutine to receive responses
	go func() {
		for {
			var responseChunk ToolInvocationStreamChunk
			if err := conn.ReadJSON(&responseChunk); err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					errChan <- nil // Normal closure
					return
				}
				errChan <- fmt.Errorf("failed to read response from A2A platform: %w", err)
				return
			}

			select {
			case responseStream <- &responseChunk:
				// Check if this is the last chunk
				if responseChunk.IsLast {
					errChan <- nil
					return
				}
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			}
		}
	}()

	// Wait for either sending or receiving to complete/error
	err = <-errChan
	if err != nil {
		log.Printf("A2APlatformAdapter: Streaming error: %v", err)
		return err
	}

	log.Printf("A2APlatformAdapter: Streaming completed successfully")
	return nil
}

func (a *A2APlatformAdapter) HealthCheck(ctx context.Context) error {
	if a.cfg.A2APlatformConfig.HubAddress == "" {
		log.Printf("A2APlatformAdapter: HealthCheck for %s skipped, HubAddress not configured.", a.name)
		return fmt.Errorf("HubAddress not configured for A2A provider %s, health check skipped", a.name)
	}

	// Assuming a common health check endpoint like /healthz or /status
	healthEndpoint := strings.TrimRight(a.cfg.A2APlatformConfig.HubAddress, "/") + "/healthz"
	log.Printf("A2APlatformAdapter: Performing HealthCheck for %s at %s", a.name, healthEndpoint)

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second) // Short timeout for health check
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, "GET", healthEndpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create A2A HealthCheck HTTP request for %s: %w", a.name, err)
	}
	if a.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.apiKey) // Or other scheme
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("health check request to A2A platform %s failed: %w", a.name, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
		log.Printf("A2APlatformAdapter: HealthCheck for provider %s successful.", a.name)
		return nil
	}

	bodyBytes, _ := io.ReadAll(httpResp.Body)
	return fmt.Errorf("A2A platform %s health check failed with status %d: %s", a.name, httpResp.StatusCode, string(bodyBytes))
}

func (a *A2APlatformAdapter) Shutdown() error {
	log.Printf("A2APlatformAdapter: Shutdown for %s (placeholder, standard http.Client typically doesn't need explicit close for connections unless Transport is custom)", a.name)
	return nil
}
