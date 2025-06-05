package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url" // For parsing ServerAddress
	"strings" // For joining paths
	"time"    // For HealthCheck timeout

	"github.com/gorilla/websocket"
	"github.com/openpons/gateway/internal/config"
	// "github.com/openpons/gateway/internal/secrets" // Replaced by SecretRetriever
)

var _ ProviderAdapter = (*MCPToolAdapter)(nil)

type MCPToolAdapter struct {
	id               string
	name             string
	cfg              config.ProviderConfig
	secretManager    SecretRetriever // Use interface
	httpClient       *http.Client
	apiKey           string // Store API key if configured
	serverScheme     string // http, https, grpc, stdio
	serverAddrParsed string // host:port or path for stdio
}

func NewMCPToolAdapter(providerCfg config.ProviderConfig, sm SecretRetriever, httpClient *http.Client) (*MCPToolAdapter, error) {
	if providerCfg.MCPToolConfig == nil {
		return nil, fmt.Errorf("MCPToolAdapter requires MCPToolConfig to be set")
	}
	rawServerAddress := providerCfg.MCPToolConfig.ServerAddress
	log.Printf("MCPToolAdapter: Initializing for provider %s (ID: %s), server: %s", providerCfg.Name, providerCfg.ID, rawServerAddress)

	var apiKeyVal string
	var err error
	if providerCfg.CredentialsSecretID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		apiKeyVal, err = sm.GetSecret(ctx, providerCfg.CredentialsSecretID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve API key for MCP provider %s (secretID: %s): %w", providerCfg.Name, providerCfg.CredentialsSecretID, err)
		}
		if apiKeyVal == "" {
			log.Printf("Warning: Retrieved API key for MCP provider %s (secretID: %s) is empty.", providerCfg.Name, providerCfg.CredentialsSecretID)
		}
	} else {
		log.Printf("Info: No CredentialsSecretID configured for MCP provider %s.", providerCfg.Name)
	}

	parsedURL, err := url.Parse(rawServerAddress)
	var scheme, addrParsed string
	if err == nil {
		scheme = strings.ToLower(parsedURL.Scheme)
		if scheme == "http" || scheme == "https" {
			addrParsed = parsedURL.String()
		} else if scheme == "grpc" {
			addrParsed = parsedURL.Host
			log.Printf("MCPToolAdapter: gRPC scheme detected for %s. HTTP client will not be used for gRPC.", providerCfg.Name)
		} else if scheme == "stdio" {
			addrParsed = strings.TrimPrefix(rawServerAddress, "stdio:")
			log.Printf("MCPToolAdapter: stdio scheme detected for %s. HTTP client will not be used for stdio.", providerCfg.Name)
		} else {
			log.Printf("MCPToolAdapter: Unknown or unsupported scheme '%s' for provider %s. Defaulting to treating address as HTTP endpoint.", scheme, providerCfg.Name)
			if !strings.Contains(rawServerAddress, "://") {
				scheme = "http"
				addrParsed = "http://" + rawServerAddress
			} else {
				scheme = "unknown"
				addrParsed = rawServerAddress
			}
		}
	} else {
		log.Printf("MCPToolAdapter: Could not parse ServerAddress '%s' as URL for provider %s: %v. Assuming it's a plain HTTP address.", rawServerAddress, providerCfg.Name, err)
		scheme = "http"
		addrParsed = "http://" + rawServerAddress
	}

	clientToUse := httpClient
	if clientToUse == nil && (scheme == "http" || scheme == "https") {
		clientToUse = &http.Client{Timeout: 30 * time.Second}
	}

	return &MCPToolAdapter{
		id:               providerCfg.ID,
		name:             providerCfg.Name,
		cfg:              providerCfg,
		secretManager:    sm,
		httpClient:       clientToUse,
		apiKey:           apiKeyVal,
		serverScheme:     scheme,
		serverAddrParsed: addrParsed,
	}, nil
}

func (a *MCPToolAdapter) Init(cfg *config.ProviderConfig, sr SecretRetriever) error {
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
			return fmt.Errorf("Init: failed to retrieve API key for MCP provider %s (secretID: %s): %w", cfg.Name, cfg.CredentialsSecretID, err)
		}
		a.apiKey = apiKeyVal
	} else {
		a.apiKey = ""
	}
	if cfg.MCPToolConfig == nil {
		a.cfg.MCPToolConfig = &config.MCPToolServerConfig{} // Ensure it's not nil for subsequent access
	}
	// Always re-parse server address based on the (potentially newly defaulted) MCPToolConfig
	rawServerAddress := a.cfg.MCPToolConfig.ServerAddress // Use a.cfg here as it's now guaranteed non-nil
	parsedURL, err := url.Parse(rawServerAddress)
	if err == nil {
		a.serverScheme = strings.ToLower(parsedURL.Scheme)
		if a.serverScheme == "http" || a.serverScheme == "https" {
			a.serverAddrParsed = parsedURL.String()
		} else if a.serverScheme == "grpc" {
			a.serverAddrParsed = parsedURL.Host
		} else if a.serverScheme == "stdio" {
			a.serverAddrParsed = strings.TrimPrefix(rawServerAddress, "stdio:")
		} else { // Unknown or empty scheme
			if !strings.Contains(rawServerAddress, "://") && rawServerAddress != "" {
				a.serverScheme = "http" // Default for plain host:port or path
				a.serverAddrParsed = "http://" + rawServerAddress
			} else if rawServerAddress == "" { // Handle explicitly empty ServerAddress
				a.serverScheme = "http"        // Default scheme
				a.serverAddrParsed = "http://" // Default to just scheme if address is empty
			} else {
				a.serverScheme = "unknown"
				a.serverAddrParsed = rawServerAddress
			}
		}
	} else { // Parsing error, treat as plain http address
		a.serverScheme = "http"
		a.serverAddrParsed = "http://" + rawServerAddress
	}

	log.Printf("MCPToolAdapter: Initialized/Re-initialized for provider %s (ID: %s), scheme: %s, address: %s", cfg.Name, cfg.ID, a.serverScheme, a.serverAddrParsed)
	return nil
}

func (a *MCPToolAdapter) ProviderInfo() Info {
	return Info{
		Name: a.name,
		Type: config.ProviderTypeToolServer,
		Capabilities: []string{
			"invoke_tool",
			"stream_invoke_tool",
		},
	}
}
func (a *MCPToolAdapter) GetConfig() *config.ProviderConfig { return &a.cfg }

func (a *MCPToolAdapter) ChatCompletion(ctx context.Context, request *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	return nil, fmt.Errorf("ChatCompletion not supported by MCPToolAdapter")
}

func (a *MCPToolAdapter) StreamChatCompletion(ctx context.Context, request *ChatCompletionRequest, stream io.Writer) error {
	return fmt.Errorf("StreamChatCompletion not supported by MCPToolAdapter")
}

func (a *MCPToolAdapter) GenerateEmbedding(ctx context.Context, request *EmbeddingRequest) (*EmbeddingResponse, error) {
	return nil, fmt.Errorf("GenerateEmbedding not supported by MCPToolAdapter")
}

func (a *MCPToolAdapter) AudioTranscription(ctx context.Context, request *AudioTranscriptionRequest) (*AudioTranscriptionResponse, error) {
	return nil, fmt.Errorf("AudioTranscription not supported by MCPToolAdapter")
}

func (a *MCPToolAdapter) TextToSpeech(ctx context.Context, request *TextToSpeechRequest, stream io.Writer) error {
	if request == nil { // Added nil check for consistency, though method returns error anyway
		return fmt.Errorf("TextToSpeechRequest cannot be nil")
	}
	return fmt.Errorf("TextToSpeech not supported by MCPToolAdapter")
}

func (a *MCPToolAdapter) InvokeTool(ctx context.Context, request *ToolInvocationRequest) (*ToolInvocationResponse, error) {
	if request == nil {
		return nil, fmt.Errorf("ToolInvocationRequest cannot be nil")
	}
	if a.serverScheme != "http" && a.serverScheme != "https" {
		log.Printf("MCPToolAdapter: InvokeTool for %s skipped, unsupported scheme: %s", a.name, a.serverScheme)
		return nil, fmt.Errorf("MCPToolAdapter for %s does not support InvokeTool with scheme '%s'", a.name, a.serverScheme)
	}
	if a.httpClient == nil {
		return nil, fmt.Errorf("MCPToolAdapter for %s has no HTTP client configured for HTTP/HTTPS scheme", a.name)
	}

	endpoint := strings.TrimRight(a.serverAddrParsed, "/") + "/invoke/" + request.ToolName
	log.Printf("MCPToolAdapter: Invoking tool '%s' at endpoint '%s'", request.ToolName, endpoint)

	reqBodyBytes, err := json.Marshal(request.Arguments)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MCP request arguments for tool %s: %w", request.ToolName, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP HTTP request for tool %s: %w", request.ToolName, err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to MCP server for tool %s: %w", request.ToolName, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		var toolErr ToolError
		if json.Unmarshal(bodyBytes, &toolErr) == nil && toolErr.Message != "" {
			return &ToolInvocationResponse{Error: &toolErr}, nil
		}
		return nil, fmt.Errorf("MCP server request for tool %s failed with status %d: %s", request.ToolName, httpResp.StatusCode, string(bodyBytes))
	}

	var toolResp ToolInvocationResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&toolResp); err != nil {
		log.Printf("MCPToolAdapter: Successfully invoked tool %s, but failed to decode response into ToolInvocationResponse struct: %v.", request.ToolName, err)
		return nil, fmt.Errorf("failed to decode MCP server response for tool %s: %w", request.ToolName, err)
	}

	log.Printf("MCPToolAdapter: Successfully invoked tool %s", request.ToolName)
	return &toolResp, nil
}

func (a *MCPToolAdapter) StreamInvokeTool(ctx context.Context, requestStream <-chan *ToolInvocationStreamChunk, responseStream chan<- *ToolInvocationStreamChunk) error {
	if responseStream != nil {
		defer close(responseStream)
	}

	if a.serverScheme != "http" && a.serverScheme != "https" {
		return fmt.Errorf("streaming not supported for scheme: %s", a.serverScheme)
	}

	if a.httpClient == nil {
		return fmt.Errorf("MCPToolAdapter for %s has no HTTP client configured for streaming", a.name)
	}

	// Check for nil channels that would cause issues in tests
	if requestStream == nil || responseStream == nil {
		return fmt.Errorf("MCPToolAdapter: requestStream and responseStream cannot be nil")
	}

	// Build WebSocket URL from HTTP server address
	wsURL := strings.Replace(a.serverAddrParsed, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.TrimRight(wsURL, "/") + "/stream"

	log.Printf("MCPToolAdapter: Connecting to WebSocket at %s for streaming tool invocation", wsURL)

	// Create WebSocket dialer with timeout
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
	}

	// Set headers including auth if available
	headers := http.Header{}
	if a.apiKey != "" {
		headers.Set("Authorization", "Bearer "+a.apiKey)
	}

	// Establish WebSocket connection
	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return fmt.Errorf("failed to connect to MCP server WebSocket: %w", err)
	}
	defer conn.Close()

	// Handle bidirectional streaming
	errChan := make(chan error, 2)

	// Send requests from requestStream to WebSocket
	go func() {
		defer func() {
			// Send close message when done sending
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		}()

		for {
			select {
			case chunk, ok := <-requestStream:
				if !ok {
					// Request stream closed
					errChan <- nil
					return
				}

				if err := conn.WriteJSON(chunk); err != nil {
					errChan <- fmt.Errorf("failed to send chunk to MCP server: %w", err)
					return
				}

			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			}
		}
	}()

	// Receive responses from WebSocket and send to responseStream
	go func() {
		for {
			var responseChunk ToolInvocationStreamChunk
			err := conn.ReadJSON(&responseChunk)
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					// Normal close, not an error
					errChan <- nil
				} else {
					errChan <- fmt.Errorf("failed to read response from MCP server: %w", err)
				}
				return
			}

			select {
			case responseStream <- &responseChunk:
				// Successfully sent response chunk
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			}
		}
	}()

	// Wait for either goroutine to complete or error
	err = <-errChan
	if err != nil {
		log.Printf("MCPToolAdapter: StreamInvokeTool error: %v", err)
		return err
	}

	log.Printf("MCPToolAdapter: StreamInvokeTool completed successfully")
	return nil
}

func (a *MCPToolAdapter) HealthCheck(ctx context.Context) error {
	if a.serverScheme != "http" && a.serverScheme != "https" {
		log.Printf("MCPToolAdapter: HealthCheck for %s skipped, unsupported scheme: %s", a.name, a.serverScheme)
		return nil
	}
	if a.httpClient == nil {
		return fmt.Errorf("MCPToolAdapter for %s has no HTTP client configured for HTTP/HTTPS scheme health check", a.name)
	}

	healthEndpoint := strings.TrimRight(a.serverAddrParsed, "/") + "/healthz"
	log.Printf("MCPToolAdapter: Performing HealthCheck for %s at %s", a.name, healthEndpoint)

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, "GET", healthEndpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create MCP HealthCheck HTTP request for %s: %w", a.name, err)
	}
	if a.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	}

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("health check request to MCP server %s failed: %w", a.name, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
		log.Printf("MCPToolAdapter: HealthCheck for provider %s successful.", a.name)
		return nil
	}

	bodyBytes, _ := io.ReadAll(httpResp.Body)
	return fmt.Errorf("MCP server %s health check failed with status %d: %s", a.name, httpResp.StatusCode, string(bodyBytes))
}

func (a *MCPToolAdapter) Shutdown() error {
	log.Printf("MCPToolAdapter: Shutdown for %s (placeholder)", a.name)
	return nil
}
