package provider

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http" // Retained as httpClient is in the struct
	"time"

	"github.com/google/uuid"
	"github.com/openpons/gateway/internal/config"

	// "github.com/openpons/gateway/internal/secrets" // Replaced by SecretRetriever

	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/structpb"

	aiplatform "cloud.google.com/go/aiplatform/apiv1"
	"cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
	"github.com/googleapis/gax-go/v2" // Corrected import path for gax
)

var _ ProviderAdapter = (*VertexAIAdapter)(nil)

// vertexPredictionClientInterface defines the methods we need from aiplatform.PredictionClient
// to allow for mocking in tests.
type vertexPredictionClientInterface interface {
	Predict(context.Context, *aiplatformpb.PredictRequest, ...gax.CallOption) (*aiplatformpb.PredictResponse, error)
	Close() error
}

type VertexAIAdapter struct {
	id            string
	name          string
	cfg           config.ProviderConfig
	secretManager SecretRetriever // Use interface
	client        vertexPredictionClientInterface
	projectID     string
	location      string
	httpClient    *http.Client // Retained for potential future use or consistency
}

func NewVertexAIAdapter(providerCfg config.ProviderConfig, sm SecretRetriever, httpClient *http.Client) (*VertexAIAdapter, error) {
	if providerCfg.LLMConfig == nil {
		return nil, fmt.Errorf("vertexai adapter requires LLMConfig to be set")
	}

	// Get projectID and location from VertexAI config
	var projectID, location string
	if providerCfg.LLMConfig.VertexAI != nil {
		projectID = providerCfg.LLMConfig.VertexAI.ProjectID
		location = providerCfg.LLMConfig.VertexAI.Location
	}

	// Validate required configuration
	if projectID == "" {
		return nil, fmt.Errorf("VertexAI ProjectID is required in LLMConfig.VertexAI")
	}
	if location == "" {
		return nil, fmt.Errorf("VertexAI Location is required in LLMConfig.VertexAI")
	}

	var clientOptions []option.ClientOption
	if providerCfg.CredentialsSecretID != "" {
		saKeyJSON, err := sm.GetSecret(context.Background(), providerCfg.CredentialsSecretID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve SA key for VertexAI provider %s (secretID: %s): %w", providerCfg.Name, providerCfg.CredentialsSecretID, err)
		}
		if saKeyJSON == "" {
			return nil, fmt.Errorf("retrieved SA key for VertexAI provider %s is empty", providerCfg.Name)
		}
		clientOptions = append(clientOptions, option.WithCredentialsJSON([]byte(saKeyJSON)))
	} else {
		log.Printf("VertexAIAdapter: No CredentialsSecretID for %s, attempting to use Application Default Credentials.", providerCfg.Name)
	}

	clientCtx := context.Background()
	// Endpoint can be regional, e.g., "us-central1-aiplatform.googleapis.com:443"
	// If not specified, client library might use a default.
	// clientOptions = append(clientOptions, option.WithEndpoint(fmt.Sprintf("%s-aiplatform.googleapis.com:443", location)))

	predictionClient, err := aiplatform.NewPredictionClient(clientCtx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vertex AI prediction client for %s: %w", providerCfg.Name, err)
	}
	log.Printf("VertexAIAdapter: Successfully initialized Vertex AI PredictionClient for provider %s", providerCfg.Name)

	clientToUse := httpClient
	if clientToUse == nil {
		// For Vertex AI gRPC client, http.Client is not directly used for main operations,
		// but might be kept for other potential interactions or consistency.
		// clientToUse = http.DefaultClient
	}

	return &VertexAIAdapter{
		id:            providerCfg.ID,
		name:          providerCfg.Name,
		cfg:           providerCfg,
		secretManager: sm,
		client:        predictionClient,
		projectID:     projectID,
		location:      location,
		httpClient:    clientToUse,
	}, nil
}

func (a *VertexAIAdapter) Init(cfg *config.ProviderConfig, sr SecretRetriever) error {
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

	// Get projectID and location from VertexAI config
	var projectID, location string
	if cfg.LLMConfig != nil && cfg.LLMConfig.VertexAI != nil {
		projectID = cfg.LLMConfig.VertexAI.ProjectID
		location = cfg.LLMConfig.VertexAI.Location
	}

	// Validate required configuration
	if projectID == "" {
		return fmt.Errorf("VertexAI ProjectID is required in LLMConfig.VertexAI for Init")
	}
	if location == "" {
		return fmt.Errorf("VertexAI Location is required in LLMConfig.VertexAI for Init")
	}

	a.projectID = projectID
	a.location = location

	var clientOptions []option.ClientOption
	if cfg.CredentialsSecretID != "" {
		saKeyJSON, err := sr.GetSecret(context.Background(), cfg.CredentialsSecretID)
		if err != nil {
			return fmt.Errorf("Init: failed to retrieve SA key for VertexAI provider %s: %w", cfg.Name, err)
		}
		clientOptions = append(clientOptions, option.WithCredentialsJSON([]byte(saKeyJSON)))
	}

	clientCtx := context.Background()
	newPredictionClient, err := aiplatform.NewPredictionClient(clientCtx, clientOptions...)
	if err != nil {
		return fmt.Errorf("Init: failed to re-create Vertex AI prediction client for %s: %w", cfg.Name, err)
	}
	if a.client != nil {
		a.client.Close()
	}
	a.client = newPredictionClient
	log.Printf("VertexAIAdapter: Initialized/Re-initialized for provider %s (ID: %s)", cfg.Name, cfg.ID)
	return nil
}

func (a *VertexAIAdapter) ProviderInfo() Info {
	return Info{
		Name: a.name,
		Type: config.ProviderTypeLLM,
		Capabilities: []string{
			"chat_completion",
			"embedding",
			// "stream_chat_completion", // Add if implemented
		},
	}
}

func (a *VertexAIAdapter) GetConfig() *config.ProviderConfig { return &a.cfg }

func messagesToVertexInstances(messages []ChatMessage) (*structpb.Value, error) {
	contents := []map[string]interface{}{}
	for _, msg := range messages {
		vertexRole := "user"
		if msg.Role == "assistant" || msg.Role == "model" {
			vertexRole = "model"
		} else if msg.Role == "system" {
			log.Printf("VertexAIAdapter: System role for message content '%s' might need special handling for Vertex AI.", msg.Content)
			continue
		}
		contents = append(contents, map[string]interface{}{
			"role":  vertexRole,
			"parts": []map[string]interface{}{{"text": msg.Content}},
		})
	}
	instanceMap := map[string]interface{}{"contents": contents}
	s, err := structpb.NewStruct(instanceMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create structpb.Struct for Vertex instance: %w", err)
	}
	return structpb.NewStructValue(s), nil
}

func (a *VertexAIAdapter) ChatCompletion(ctx context.Context, request *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	if request == nil {
		return nil, fmt.Errorf("ChatCompletionRequest cannot be nil")
	}
	if a.client == nil {
		return nil, fmt.Errorf("VertexAI client not initialized for provider %s", a.name)
	}
	modelEndpoint := fmt.Sprintf("projects/%s/locations/%s/publishers/google/models/%s", a.projectID, a.location, request.Model)
	instanceValue, err := messagesToVertexInstances(request.Messages)
	if err != nil {
		return nil, fmt.Errorf("failed to construct Vertex AI instance: %w", err)
	}
	paramsMap := make(map[string]interface{})
	if request.MaxTokens > 0 {
		paramsMap["maxOutputTokens"] = float64(request.MaxTokens)
	}
	if request.Temperature > 0 {
		paramsMap["temperature"] = float64(request.Temperature)
	}
	if request.TopP > 0 {
		paramsMap["topP"] = float64(request.TopP)
	}
	if len(request.Messages) > 0 && request.Messages[0].Role == "system" {
		systemInstructionStruct, err := structpb.NewStruct(map[string]interface{}{
			"parts": []map[string]interface{}{{"text": request.Messages[0].Content}},
		})
		if err == nil {
			paramsMap["system_instruction"] = structpb.NewStructValue(systemInstructionStruct)
		} else {
			log.Printf("VertexAIAdapter: Failed to create struct for system_instruction: %v", err)
		}
	}

	var parameters *structpb.Value
	if len(paramsMap) > 0 {
		ps, err_param := structpb.NewStruct(paramsMap)
		if err_param != nil {
			return nil, fmt.Errorf("failed to create structpb.Struct for Vertex AI parameters: %w", err_param)
		}
		parameters = structpb.NewStructValue(ps)
	}
	vertexReq := &aiplatformpb.PredictRequest{
		Endpoint:   modelEndpoint,
		Instances:  []*structpb.Value{instanceValue},
		Parameters: parameters,
	}
	log.Printf("VertexAIAdapter: Sending PredictRequest to endpoint %s for model %s", vertexReq.Endpoint, request.Model)
	vertexResp, err := a.client.Predict(ctx, vertexReq)
	if err != nil {
		return nil, fmt.Errorf("Vertex AI Predict API call failed: %w", err)
	}
	if len(vertexResp.Predictions) == 0 {
		return nil, fmt.Errorf("Vertex AI returned no predictions")
	}
	prediction := vertexResp.Predictions[0]
	var responseContent string
	if candidatesVal, ok := prediction.GetStructValue().GetFields()["candidates"]; ok {
		candidates := candidatesVal.GetListValue().GetValues()
		if len(candidates) > 0 {
			candidate := candidates[0].GetStructValue()
			if contentVal, ok := candidate.GetFields()["content"]; ok {
				contentStruct := contentVal.GetStructValue()
				if partsVal, ok := contentStruct.GetFields()["parts"]; ok {
					parts := partsVal.GetListValue().GetValues()
					if len(parts) > 0 {
						if textVal, ok := parts[0].GetStructValue().GetFields()["text"]; ok {
							responseContent = textVal.GetStringValue()
						}
					}
				}
			}
		}
	} else {
		if sVal, ok := prediction.GetStructValue().GetFields()["content"]; ok {
			responseContent = sVal.GetStringValue()
		} else {
			return nil, fmt.Errorf("Vertex AI prediction in unexpected format: %v", prediction.String())
		}
	}
	resp := &ChatCompletionResponse{
		ID:      uuid.New().String(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   request.Model,
		Choices: []ChatCompletionResponseChoice{
			{
				Index:   0,
				Message: ChatMessage{Role: "assistant", Content: responseContent},
			},
		},
	}
	log.Printf("VertexAIAdapter: Successfully completed ChatCompletion for model %s", request.Model)
	return resp, nil
}

func (a *VertexAIAdapter) StreamChatCompletion(ctx context.Context, request *ChatCompletionRequest, stream io.Writer) error {
	if request == nil {
		return fmt.Errorf("ChatCompletionRequest cannot be nil")
	}
	if a.client == nil {
		return fmt.Errorf("VertexAI client not initialized for provider %s", a.name)
	}
	log.Printf("VertexAIAdapter: StreamChatCompletion for model %s. True streaming requires model-specific client or REST SSE handling.", request.Model)
	return fmt.Errorf("VertexAIAdapter.StreamChatCompletion not fully implemented for generic PredictionClient; requires model-specific streaming logic")
}

func embeddingRequestToVertexInstance(input string) (*structpb.Value, error) {
	instanceMap := map[string]interface{}{"content": input}
	s, err := structpb.NewStruct(instanceMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create structpb.Struct for Vertex AI embedding instance: %w", err)
	}
	return structpb.NewStructValue(s), nil
}

func (a *VertexAIAdapter) GenerateEmbedding(ctx context.Context, request *EmbeddingRequest) (*EmbeddingResponse, error) {
	if request == nil {
		return nil, fmt.Errorf("EmbeddingRequest cannot be nil")
	}
	if a.client == nil {
		return nil, fmt.Errorf("VertexAI client not initialized for provider %s", a.name)
	}
	var instances []*structpb.Value
	var inputs []string
	switch v := request.Input.(type) {
	case string:
		inputs = []string{v}
	case []string:
		inputs = v
	default:
		return nil, fmt.Errorf("unsupported type for VertexAI embedding input: %T", request.Input)
	}
	for _, inputText := range inputs {
		instanceVal, err := embeddingRequestToVertexInstance(inputText)
		if err != nil {
			return nil, fmt.Errorf("failed to construct Vertex AI embedding instance for input '%s': %w", inputText, err)
		}
		instances = append(instances, instanceVal)
	}
	vertexReq := &aiplatformpb.PredictRequest{
		Endpoint:  fmt.Sprintf("projects/%s/locations/%s/publishers/google/models/%s", a.projectID, a.location, request.Model),
		Instances: instances,
	}
	log.Printf("VertexAIAdapter: Sending PredictRequest to endpoint %s for embedding model %s", vertexReq.Endpoint, request.Model)
	vertexResp, err := a.client.Predict(ctx, vertexReq)
	if err != nil {
		return nil, fmt.Errorf("Vertex AI embedding Predict API call failed: %w", err)
	}
	if len(vertexResp.Predictions) == 0 || len(vertexResp.Predictions) != len(inputs) {
		return nil, fmt.Errorf("Vertex AI returned unexpected number of predictions for embeddings (got %d, expected %d)", len(vertexResp.Predictions), len(inputs))
	}
	embeddings := make([]Embedding, len(vertexResp.Predictions))
	for i, predictionProto := range vertexResp.Predictions {
		predictionStruct := predictionProto.GetStructValue()
		if predictionStruct == nil {
			return nil, fmt.Errorf("Vertex AI embedding prediction %d is not a struct", i)
		}
		embeddingsField, ok := predictionStruct.GetFields()["embeddings"]
		if !ok {
			return nil, fmt.Errorf("Vertex AI embedding prediction %d missing 'embeddings' field", i)
		}
		embeddingStruct := embeddingsField.GetStructValue()
		if embeddingStruct == nil {
			return nil, fmt.Errorf("Vertex AI 'embeddings' field for prediction %d is not a struct", i)
		}
		valuesField, ok := embeddingStruct.GetFields()["values"]
		if !ok {
			return nil, fmt.Errorf("Vertex AI embedding %d missing 'values' field", i)
		}
		valuesList := valuesField.GetListValue()
		if valuesList == nil {
			return nil, fmt.Errorf("Vertex AI embedding 'values' field for prediction %d is not a list", i)
		}
		floatEmbedding := make([]float32, len(valuesList.GetValues()))
		for j, valProto := range valuesList.GetValues() {
			floatEmbedding[j] = float32(valProto.GetNumberValue())
		}
		embeddings[i] = Embedding{
			Object:    "embedding",
			Embedding: floatEmbedding,
			Index:     i,
		}
	}
	resp := &EmbeddingResponse{
		Object: "list",
		Data:   embeddings,
		Model:  request.Model,
	}
	log.Printf("VertexAIAdapter: Successfully generated embeddings for model %s, count: %d", request.Model, len(embeddings))
	return resp, nil
}

func (a *VertexAIAdapter) AudioTranscription(ctx context.Context, request *AudioTranscriptionRequest) (*AudioTranscriptionResponse, error) {
	if request == nil {
		return nil, fmt.Errorf("AudioTranscriptionRequest cannot be nil")
	}

	// VertexAI supports speech-to-text through the Speech API, not the Prediction API
	// This would require a separate Speech client and different authentication/configuration
	log.Printf("VertexAIAdapter: AudioTranscription called for model %s", request.Model)

	return nil, fmt.Errorf("VertexAI AudioTranscription requires the Speech API client which is not currently implemented. Use the dedicated Speech-to-Text API instead of the Prediction API")
}

func (a *VertexAIAdapter) TextToSpeech(ctx context.Context, request *TextToSpeechRequest, stream io.Writer) error {
	if request == nil {
		return fmt.Errorf("TextToSpeechRequest cannot be nil")
	}
	if stream == nil {
		return fmt.Errorf("output stream cannot be nil")
	}

	// VertexAI supports text-to-speech through the Text-to-Speech API, not the Prediction API
	// This would require a separate TTS client and different authentication/configuration
	log.Printf("VertexAIAdapter: TextToSpeech called for model %s", request.Model)

	return fmt.Errorf("VertexAI TextToSpeech requires the Text-to-Speech API client which is not currently implemented. Use the dedicated Cloud Text-to-Speech API instead of the Prediction API")
}

func (a *VertexAIAdapter) InvokeTool(ctx context.Context, request *ToolInvocationRequest) (*ToolInvocationResponse, error) {
	if request == nil {
		return nil, fmt.Errorf("ToolInvocationRequest cannot be nil")
	}
	return nil, fmt.Errorf("VertexAIAdapter does not support InvokeTool directly as an LLM provider")
}

func (a *VertexAIAdapter) StreamInvokeTool(ctx context.Context, requestStream <-chan *ToolInvocationStreamChunk, responseStream chan<- *ToolInvocationStreamChunk) error {
	log.Printf("VertexAIAdapter: StreamInvokeTool called (placeholder)")
	if responseStream != nil {
		close(responseStream)
	}
	if requestStream != nil {
		go func() {
			for range requestStream {
				// Drain the channel
			}
		}()
	}
	return fmt.Errorf("VertexAIAdapter.StreamInvokeTool not supported by generic PredictionClient")
}

func (a *VertexAIAdapter) HealthCheck(ctx context.Context) error {
	log.Printf("VertexAIAdapter: HealthCheck called for provider %s", a.name)
	if a.client == nil {
		return fmt.Errorf("VertexAI client not initialized for provider %s, health check failed", a.name)
	}
	log.Printf("VertexAIAdapter: HealthCheck for provider %s successful (client initialized).", a.name)
	return nil
}

func (a *VertexAIAdapter) Shutdown() error {
	log.Printf("VertexAIAdapter: Shutdown called for provider %s", a.name)
	if a.client != nil {
		if err := a.client.Close(); err != nil {
			log.Printf("Error closing Vertex AI client for provider %s: %v", a.name, err)
			return err
		}
	}
	return nil
}
