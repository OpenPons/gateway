package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"time"

	// "io" // For streaming to response

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap" // Added for zap.String, zap.Error

	// "go.opentelemetry.io/otel/attribute" // For OTel attributes
	// semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	// "go.opentelemetry.io/otel/trace"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam"
	"github.com/openpons/gateway/internal/pluginruntime"
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/routing"
	"github.com/openpons/gateway/internal/telemetry"
)

// ChatProxyHandler handles proxied chat completion requests.
type ChatProxyHandler struct {
	router        routing.RouterInterface
	iamService    iam.ServiceInterface
	pluginManager pluginruntime.ManagerInterface
	// providerRegistry provider.RegistryInterface // If it were needed
}

// NewChatProxyHandler creates a new handler for chat completions.
func NewChatProxyHandler(r routing.RouterInterface, iamSvc iam.ServiceInterface, pm pluginruntime.ManagerInterface) *ChatProxyHandler {
	return &ChatProxyHandler{
		router:        r,
		iamService:    iamSvc,
		pluginManager: pm,
	}
}

// ServeHTTP handles the /proxy/models/{modelId}/chat/completions endpoint.
// It uses the iamService's AuthMiddleware for authentication and authorization.
func (h *ChatProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Wrap the core logic with the IAM service's authentication middleware.
	// The iam.Service.AuthMiddleware itself returns an http.Handler.
	// We need to ensure our iamService field is compatible or we adapt.
	// Assuming h.iamService is a struct that has an AuthMiddleware method.
	// If iamService is an interface, it must declare AuthMiddleware.

	// For this to work, iam.ServiceInterface needs to declare AuthMiddleware,
	// or we cast h.iamService to a concrete type that has it, or we adjust NewChatProxyHandler.
	// Let's assume iam.ServiceInterface will be updated or we have a concrete type.
	// For now, to proceed, we'll assume h.iamService has AuthMiddleware.
	// If not, this will be a compile error to fix by adjusting interface or instantiation.

	// The AuthMiddleware in iam.go is on the *Service struct, not the ServiceInterface.
	// This means we either need to:
	// 1. Add AuthMiddleware to ServiceInterface.
	// 2. Change ChatProxyHandler to take *iam.Service instead of iam.ServiceInterface.
	// 3. Create a small adapter or expect the caller of NewChatProxyHandler to provide a handler
	//    that's already wrapped with necessary auth.

	// Option 1 is cleanest for decoupling. Let's proceed assuming ServiceInterface will have AuthMiddleware.
	// If it doesn't, we'll get a compile error and fix the interface.
	authHandler := h.iamService.AuthMiddleware(http.HandlerFunc(h.handleChatCompletionsLogic))
	authHandler.ServeHTTP(w, r)
}

// handleChatCompletionsLogic contains the core logic after authentication and authorization.
func (h *ChatProxyHandler) handleChatCompletionsLogic(w http.ResponseWriter, r *http.Request) {
	// ctx, span := telemetry.Tracer.Start(r.Context(), "ChatProxyHandler.handleChatCompletionsLogic")
	// defer span.End()

	modelID := chi.URLParam(r, "modelId")
	// span.SetAttributes(attribute.String("model_id", modelID))
	telemetry.Logger.Debug("Processing chat completion request", zap.String("model_id", modelID))

	// Authentication & Authorization should have been handled by the iamService.AuthMiddleware.
	// Now, check specific permission for this operation using context values set by that middleware.
	principalIDVal := r.Context().Value(iam.ContextKeyPrincipalID)
	principalID, ok := principalIDVal.(string)
	if !ok || principalID == "" {
		// This should ideally be caught by AuthMiddleware if it requires authentication.
		// If AuthMiddleware allows anonymous but we require auth here, this check is valid.
		telemetry.Logger.Warn("Principal ID not found in context or is empty after auth middleware", zap.Any("principalIDVal", principalIDVal))
		http.Error(w, "Forbidden: Authentication required", http.StatusForbidden)
		return
	}

	authInfo := r.Context().Value(iam.ContextKeyAuthInfo)
	// The permission string should match how permissions are defined (e.g., "proxy:invoke:model_id" or "llm:chat:<model_id>")
	requiredPermission := config.Permission("proxy:invoke:" + modelID) // Assuming config.Permission is string alias

	if !h.iamService.CheckPermission(r.Context(), principalID, authInfo, requiredPermission) {
		// Fallback to a general permission
		generalPermission := config.Permission("proxy:invoke")
		if !h.iamService.CheckPermission(r.Context(), principalID, authInfo, generalPermission) {
			telemetry.Logger.Warn("Permission denied for chat completion",
				zap.String("principal_id", principalID),
				zap.String("required_permission", string(requiredPermission)),
				zap.String("general_permission_attempted", string(generalPermission)))
			http.Error(w, "Forbidden: Insufficient permissions for this operation", http.StatusForbidden)
			return
		}
		telemetry.Logger.Debug("Permission granted for chat completion via general permission",
			zap.String("principal_id", principalID),
			zap.String("permission", string(generalPermission)))
	} else {
		telemetry.Logger.Debug("Permission granted for chat completion via model-specific permission",
			zap.String("principal_id", principalID),
			zap.String("permission", string(requiredPermission)))
	}

	// 1. Decode the incoming OpenAI-style request
	var chatReq provider.ChatCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&chatReq); err != nil {
		// span.RecordError(err)
		// span.SetStatus(codes.Error, "Invalid request body")
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	chatReq.Model = modelID // Ensure modelID from path is used

	// 2. Create IncomingRequestContext for routing
	reqCtx := routing.IncomingRequestContext{
		Path:     r.URL.Path,
		Method:   r.Method,
		Headers:  r.Header,
		ModelID:  modelID,
		Protocol: config.ProtocolHTTPLLM,
		// UserPrincipal: principal, // This field is commented out in routing.go
	}

	// 3. Resolve Route using the router
	resolvedTarget, err := h.router.ResolveRoute(r.Context(), reqCtx)
	if err != nil {
		// span.RecordError(err)
		// span.SetStatus(codes.Error, "Route resolution failed")
		http.Error(w, fmt.Sprintf("Could not resolve route: %v", err), http.StatusInternalServerError)
		return
	}
	// span.SetAttributes(attribute.String("route_id", resolvedTarget.Route.ID))
	// span.SetAttributes(attribute.String("target_ref", resolvedTarget.Target.Ref))

	// 4. Authentication/Authorization is now handled by the middleware wrapping this.

	// 5. Plugin Hook Invocation (Pre-Request) - Placeholder
	// for _, pluginCfg := range resolvedTarget.Route.Plugins.Pre {
	//  pluginClient, err := h.pluginManager.GetPluginClient(pluginCfg.ID)
	//  if err != nil { /* handle error */ continue }
	//  // Call pluginClient.PreHandleRequest - this needs complex stream handling
	// }

	// 6. Target Invocation
	adapter := resolvedTarget.Adapter
	policy := resolvedTarget.Route.Policy // Get the policy for this route

	if chatReq.Stream {
		// Timeout for starting the stream
		timeoutMs := policy.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = 30000 // Default timeout if not set in policy
		}
		streamCtx, streamCancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond)
		defer streamCancel()

		// Handle streaming response
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		// sseWriter := sse.NewWriter(w) // Hypothetical SSE writer
		// err = adapter.StreamChatCompletion(ctx, chatReq, sseWriter)
		// if err != nil {
		//    // Hard to send HTTP error once stream started. Log and close.
		//    telemetry.Logger.Error("Error during stream chat completion", zap.Error(err))
		//    // span.RecordError(err)
		// }
		telemetry.Logger.Info("Streaming chat completion (placeholder)", zap.String("model_id", modelID))
		fmt.Fprintf(w, "data: {\"id\":\"placeholder_stream_id\",\"object\":\"chat.completion.chunk\",\"created\":%d,\"model\":\"%s\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Streaming... (placeholder)\"},\"finish_reason\":null}]}\n\n", time.Now().Unix(), modelID)
		// Simulate end of stream
		// fmt.Fprintf(w, "data: {\"id\":\"placeholder_stream_id\",\"object\":\"chat.completion.chunk\",\"created\":%d,\"model\":\"%s\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n", time.Now().Unix(), modelID)
		// fmt.Fprintf(w, "data: [DONE]\n\n")
		// Actual streaming call
		err = adapter.StreamChatCompletion(streamCtx, &chatReq, w) // Pass address of chatReq
		if err != nil {
			// Hard to send HTTP error once stream started. Log and potentially try to write an error event if protocol supports.
			telemetry.Logger.Error("Error during stream chat completion", zap.Error(err), zap.String("route_id", resolvedTarget.Route.ID))
			// If headers not sent, can still send an error
			// This check is imperfect. A ResponseWriter wrapper is better.
			if r.ProtoMajor == 1 && r.ProtoMinor == 1 && w.Header().Get("Content-Length") == "" {
				// Use the error mapping helper
				statusCode, clientMsg := mapProviderErrorToHTTPStatus(err, http.StatusServiceUnavailable, "")
				http.Error(w, clientMsg, statusCode)
			}
		}

	} else {
		// Handle unary response with retries and timeout
		var resp *provider.ChatCompletionResponse
		var lastErr error

		attempts := 1
		if policy.RetryOnFailure && policy.RetryAttempts > 0 {
			attempts += policy.RetryAttempts
		}

		for i := 0; i < attempts; i++ {
			timeoutMs := policy.TimeoutMs
			if timeoutMs == 0 {
				timeoutMs = 30000 // Default timeout
			}
			callCtx, callCancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond)

			resp, err = adapter.ChatCompletion(callCtx, &chatReq) // Pass address of chatReq
			callCancel()                                          // Release context resources promptly

			if err == nil {
				lastErr = nil // Clear last error on success
				break         // Success
			}
			lastErr = err // Store last error

			if i < attempts-1 { // If more retries are allowed
				telemetry.Logger.Warn("ChatCompletion attempt failed, retrying...",
					zap.Int("attempt", i+1),
					zap.Int("max_attempts", attempts),
					zap.String("route_id", resolvedTarget.Route.ID),
					zap.Error(err))
				// Implement exponential backoff with jitter
				backoffDuration := calculateBackoff(i + 1) // Pass attempt number (1-based)
				telemetry.Logger.Info("Retrying with backoff",
					zap.Duration("delay", backoffDuration),
					zap.Int("attempt", i+1))
				time.Sleep(backoffDuration)
			}
		}

		if lastErr != nil {
			// All attempts failed
			telemetry.Logger.Error("ChatCompletion failed after all retry attempts",
				zap.Int("attempts", attempts),
				zap.String("route_id", resolvedTarget.Route.ID),
				zap.Error(lastErr))
			// If all attempts failed, map the error to an HTTP status code and return it.
			// The dummy adapter check is removed as dummyAdapter itself is removed.
			// All provider errors should now be treated as real errors.
			statusCode, clientMsg := mapProviderErrorToHTTPStatus(lastErr, http.StatusServiceUnavailable, "Failed to get chat completion after all attempts")
			http.Error(w, clientMsg, statusCode)
			return
		}

		// 7. Plugin Hook Invocation (Post-Response) - Placeholder

		// 8. Response Formatting
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			telemetry.Logger.Error("Failed to encode response", zap.Error(err))
			// span.RecordError(err)
		}
	}
	// 9. Telemetry is implicitly handled by middleware and direct calls for specific events.
}

// Helper to add this handler to a Chi router
// Updated signature to include all necessary dependencies for all proxy handlers.
func RegisterProxyRoutes(
	r chi.Router,
	cfgMgr config.ManagerInterface,
	iamSvc iam.ServiceInterface,
	router routing.RouterInterface,
	registry provider.RegistryInterface,
	pluginMgr pluginruntime.ManagerInterface,
	logger *zap.Logger, // Main application logger
) {
	// Chat Handler
	chatHandler := NewChatProxyHandler(router, iamSvc, pluginMgr)
	r.Post("/proxy/models/{modelID}/chat/completions", chatHandler.ServeHTTP)

	// Embedding Handler
	embeddingHandler := NewEmbeddingProxyHandler(cfgMgr, iamSvc, router, registry, pluginMgr, logger)
	r.Post("/proxy/models/{modelID}/embeddings", embeddingHandler.ServeHTTP)

	// Tool Handler
	toolHandler := NewToolProxyHandler(cfgMgr, iamSvc, router, registry, pluginMgr, logger)
	r.Post("/proxy/tools/{toolID}/invoke", toolHandler.ServeHTTP)

	// Audio Transcription Handler
	audioTranscriptionHandler := NewAudioTranscriptionProxyHandler(cfgMgr, iamSvc, router, registry, pluginMgr, logger)
	r.Post("/proxy/models/{modelID}/audio/transcriptions", audioTranscriptionHandler.ServeHTTP)

	// Text-to-Speech Handler
	textToSpeechHandler := NewTextToSpeechProxyHandler(cfgMgr, iamSvc, router, registry, pluginMgr, logger)
	r.Post("/proxy/models/{modelID}/audio/speech", textToSpeechHandler.ServeHTTP)

	logger.Info("Proxy routes registered for chat, embeddings, tools, and audio services.")
}

const (
	baseBackoffDelayMs = 100  // 100 milliseconds
	maxBackoffDelayMs  = 5000 // 5 seconds
	backoffMultiplier  = 2.0
	jitterFactor       = 0.1 // +/- 10%
)

// calculateBackoff computes an exponential backoff duration with jitter.
// attemptNum is 1-based.
func calculateBackoff(attemptNum int) time.Duration {
	if attemptNum <= 0 {
		attemptNum = 1
	}

	// Exponential backoff: baseDelay * (multiplier ^ (attemptNum - 1))
	backoff := float64(baseBackoffDelayMs) * math.Pow(backoffMultiplier, float64(attemptNum-1))

	// Cap at maxDelay
	if backoff > float64(maxBackoffDelayMs) {
		backoff = float64(maxBackoffDelayMs)
	}

	// Add jitter: +/- jitterFactor * backoff
	// jitter := (rand.Float64() * 2 * jitterFactor * backoff) - (jitterFactor * backoff) // Center around 0
	// A simpler jitter: random amount between 0 and jitterFactor * backoff, then can be added or subtracted, or just add positive jitter
	// For simplicity, let's add a random positive jitter up to jitterFactor * backoff
	// rand.Seed(time.Now().UnixNano()) // Seeding here is problematic in concurrent scenarios. Global seed or pass rand.Rand
	// Using global rand for now, ensure it's seeded once at application start.
	// Or, create a new rand.Source for each call if performance is not critical and concurrency safety is desired without locks.
	// For this specific use case, a shared rand might be fine if contention is low.
	// Let's use a new source for safety, though less performant.
	// Note: For high-performance scenarios, a shared, locked rand.Rand or sync.Pool of rand.Rand would be better.
	localRand := rand.New(rand.NewSource(time.Now().UnixNano())) // Create a new rand.Source for each call for thread-safety without global lock
	jitterVal := localRand.Float64() * jitterFactor * backoff    // Positive jitter

	finalDelay := backoff + jitterVal
	if finalDelay > float64(maxBackoffDelayMs) { // Ensure jitter doesn't exceed max
		finalDelay = float64(maxBackoffDelayMs)
	}
	if finalDelay < 0 { // Ensure jitter doesn't make it negative (shouldn't with positive jitter)
		finalDelay = 0
	}

	return time.Duration(finalDelay) * time.Millisecond
}
