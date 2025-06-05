package proxy

import (
	"encoding/json" // Ensure this is present
	"fmt"

	// "io" // Will be used by file operations if not optimized away
	// "mime/multipart" // Will be used by r.FormFile if not optimized away
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam"
	"github.com/openpons/gateway/internal/pluginruntime"
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/routing"
	// "github.com/openpons/gateway/internal/telemetry" // Will be removed if NewNopLogger is replaced
)

// AudioTranscriptionProxyHandler handles requests for audio transcriptions.
type AudioTranscriptionProxyHandler struct {
	logger           *zap.Logger
	configMgr        config.ManagerInterface
	iamService       iam.ServiceInterface
	router           routing.RouterInterface
	providerRegistry provider.RegistryInterface
	pluginManager    pluginruntime.ManagerInterface
}

// NewAudioTranscriptionProxyHandler creates a new handler for audio transcription requests.
func NewAudioTranscriptionProxyHandler(
	cfgMgr config.ManagerInterface,
	iamSvc iam.ServiceInterface,
	router routing.RouterInterface,
	registry provider.RegistryInterface,
	pluginMgr pluginruntime.ManagerInterface,
	log *zap.Logger,
) *AudioTranscriptionProxyHandler {
	if log == nil {
		log = zap.NewNop() // Use zap.NewNop()
	}
	return &AudioTranscriptionProxyHandler{
		logger:           log.Named("audio-transcription-proxy"),
		configMgr:        cfgMgr,
		iamService:       iamSvc,
		router:           router,
		providerRegistry: registry,
		pluginManager:    pluginMgr,
	}
}

// ServeHTTP processes the audio transcription request.
// It uses the iamService's AuthMiddleware for authentication and authorization.
func (h *AudioTranscriptionProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHandler := h.iamService.AuthMiddleware(http.HandlerFunc(h.handleAudioTranscriptionLogic))
	authHandler.ServeHTTP(w, r)
}

// handleAudioTranscriptionLogic contains the core logic after authentication and authorization.
func (h *AudioTranscriptionProxyHandler) handleAudioTranscriptionLogic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modelID := chi.URLParam(r, "modelID")

	// Parse multipart form
	// Max 50MB file size limit for audio, adjust as needed
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse multipart form: %v", err), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Invalid file upload: 'file' field missing or invalid", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Populate provider.AudioTranscriptionRequest from form fields
	transReq := provider.AudioTranscriptionRequest{
		File:           file,
		FileName:       handler.Filename,
		Model:          modelID, // Default to modelID from path, can be overridden by form field
		Language:       r.FormValue("language"),
		Prompt:         r.FormValue("prompt"),
		ResponseFormat: r.FormValue("response_format"),
		// Temperature: Parse from r.FormValue("temperature") if needed
	}
	formModelVal := r.FormValue("model")
	if formModelVal != "" { // Allow model override from form
		transReq.Model = formModelVal
	}
	// If model was in form and differs from path, or if only path model is used.
	// This ensures transReq.Model is definitively set.
	if transReq.Model != modelID && formModelVal == "" { // If only path model was set initially and form is empty
		// This case is fine, transReq.Model is already modelID
	} else if transReq.Model != modelID && formModelVal != "" && formModelVal != modelID { // form model differs from path model
		h.logger.Warn("Model ID in path differs from model in form, using model from path",
			zap.String("path_model_id", modelID),
			zap.String("form_model_id", formModelVal))
		transReq.Model = modelID // Prioritize path model ID
	} else if formModelVal == modelID { // form model matches path model
		transReq.Model = modelID
	}
	// If transReq.Model was initially modelID and formModelVal was also modelID, it's fine.
	// If transReq.Model was initially modelID and formModelVal was empty, it's fine.

	h.logger.Info("Received audio transcription request",
		zap.String("model_id", transReq.Model),
		zap.String("filename", transReq.FileName),
		zap.String("language", transReq.Language),
		zap.String("response_format", transReq.ResponseFormat))

	// 1. Route Resolution
	routeCtx := routing.IncomingRequestContext{
		Path:     r.URL.Path,
		Method:   r.Method,
		Headers:  r.Header,
		ModelID:  modelID, // User-facing model ID from path
		Protocol: config.ProtocolHTTPLLM,
	}
	resolvedTarget, err := h.router.ResolveRoute(ctx, routeCtx)
	if err != nil {
		h.logger.Error("Failed to resolve route for audio transcription", zap.String("model_id", modelID), zap.Error(err))
		http.Error(w, "Route not found or routing error: "+err.Error(), http.StatusNotFound)
		return
	}
	if resolvedTarget.Adapter == nil {
		h.logger.Error("Route resolved but no adapter found for audio transcription", zap.String("model_id", modelID), zap.String("route_id", resolvedTarget.Route.ID))
		http.Error(w, "Internal server error: adapter not found for resolved route", http.StatusInternalServerError)
		return
	}

	// 2. IAM Check
	principalID, _ := ctx.Value(iam.ContextKeyPrincipalID).(string)
	authInfo := ctx.Value(iam.ContextKeyAuthInfo)

	if principalID == "" {
		h.logger.Warn("No principal found in context for audio transcription, denying.", zap.String("model_id", modelID), zap.String("route_id", resolvedTarget.Route.ID))
		http.Error(w, "Forbidden: Authentication required.", http.StatusForbidden)
		return
	}

	modelSpecificPermission := config.Permission(fmt.Sprintf("proxy:invoke:audiotranscription:%s", modelID))
	generalAudioPermission := config.Permission("proxy:invoke:audiotranscription")
	generalProxyPermission := config.Permission("proxy:invoke")

	if !h.iamService.CheckPermission(ctx, principalID, authInfo, modelSpecificPermission) &&
		!h.iamService.CheckPermission(ctx, principalID, authInfo, generalAudioPermission) &&
		!h.iamService.CheckPermission(ctx, principalID, authInfo, generalProxyPermission) {
		h.logger.Warn("Permission denied for audio transcription",
			zap.String("principal_id", principalID),
			zap.String("model_id", modelID),
			zap.String("route_id", resolvedTarget.Route.ID),
			zap.String("permission_attempted_model", string(modelSpecificPermission)),
			zap.String("permission_attempted_audio", string(generalAudioPermission)),
			zap.String("permission_attempted_proxy", string(generalProxyPermission)))
		http.Error(w, "Forbidden: You do not have permission for this audio transcription.", http.StatusForbidden)
		return
	}
	h.logger.Info("IAM check passed for audio transcription", zap.String("principal_id", principalID), zap.String("model_id", modelID))

	// Get UpstreamModelName from resolved ModelConfig
	currentFullConfig := h.configMgr.GetCurrentConfig()
	var upstreamModelName string
	var targetModelConfig *config.ModelConfig
	if currentFullConfig != nil {
		for _, mc := range currentFullConfig.Models {
			if mc.ID == resolvedTarget.Target.Ref { // resolvedTarget.Target.Ref is the ModelConfig ID
				targetModelConfig = &mc
				upstreamModelName = mc.UpstreamModelName
				break
			}
		}
	}
	if targetModelConfig == nil {
		h.logger.Error("ModelConfig not found for resolved target ref for audio transcription", zap.String("target_ref", resolvedTarget.Target.Ref), zap.String("model_id", modelID))
		http.Error(w, "Internal server error: Model configuration missing for resolved route", http.StatusInternalServerError)
		return
	}
	// Update transReq.Model to the upstream name for the provider
	transReq.Model = upstreamModelName

	// 3. Pre-Request Plugin Hooks
	// Note: Plugins operating on multipart forms can be complex.
	// Passing *http.Request to plugins might be more flexible here than the parsed transReq.
	// For now, let's assume plugins can handle provider.AudioTranscriptionRequest.
	modifiedReqInterface, err := h.pluginManager.ExecutePreRequestHooks(ctx, resolvedTarget.Route, r, transReq)
	if err != nil {
		h.logger.Error("Error executing pre-request plugins for audio transcription", zap.String("model_id", modelID), zap.Error(err))
		http.Error(w, "Plugin error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	finalTransReq, ok := modifiedReqInterface.(provider.AudioTranscriptionRequest)
	if !ok {
		h.logger.Error("Pre-request plugin returned unexpected type for audio transcription request", zap.String("model_id", modelID))
		http.Error(w, "Plugin error: type mismatch after pre-request hooks", http.StatusInternalServerError)
		return
	}

	// 4. Provider Invocation
	transResp, err := resolvedTarget.Adapter.AudioTranscription(ctx, &finalTransReq)
	if err != nil {
		h.logger.Error("Error generating transcription from provider", zap.Error(err), zap.String("provider_id", resolvedTarget.Adapter.GetConfig().ID))
		http.Error(w, fmt.Sprintf("Failed to generate transcription: %v", err), http.StatusInternalServerError)
		return
	}

	// 5. Post-Request Plugin Hooks
	finalRespInterface, err := h.pluginManager.ExecutePostRequestHooks(ctx, resolvedTarget.Route, r, transResp)
	if err != nil {
		h.logger.Error("Error executing post-request plugins for audio transcription", zap.String("model_id", modelID), zap.Error(err))
		http.Error(w, "Plugin error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	finalTransResp, ok := finalRespInterface.(*provider.AudioTranscriptionResponse)
	if !ok {
		h.logger.Error("Post-request plugin returned unexpected type for audio transcription response", zap.String("model_id", modelID))
		http.Error(w, "Plugin error: type mismatch after post-request hooks", http.StatusInternalServerError)
		return
	}

	// 6. Response format handling
	// OpenAI's API returns JSON if response_format is json/verbose_json, otherwise plain text/srt/vtt.
	// This handler should ideally respect that. For now, always return JSON from our struct.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(finalTransResp); err != nil { // Changed transResp to finalTransResp
		h.logger.Error("Failed to write transcription response", zap.Error(err))
	}
}

// --- TextToSpeechProxyHandler ---

// TextToSpeechProxyHandler handles requests for text-to-speech synthesis.
type TextToSpeechProxyHandler struct {
	logger           *zap.Logger
	configMgr        config.ManagerInterface
	iamService       iam.ServiceInterface
	router           routing.RouterInterface
	providerRegistry provider.RegistryInterface
	pluginManager    pluginruntime.ManagerInterface
}

// NewTextToSpeechProxyHandler creates a new handler for TTS requests.
func NewTextToSpeechProxyHandler(
	cfgMgr config.ManagerInterface,
	iamSvc iam.ServiceInterface,
	router routing.RouterInterface,
	registry provider.RegistryInterface,
	pluginMgr pluginruntime.ManagerInterface,
	log *zap.Logger,
) *TextToSpeechProxyHandler {
	if log == nil {
		log = zap.NewNop() // Use zap.NewNop()
	}
	return &TextToSpeechProxyHandler{
		logger:           log.Named("tts-proxy"),
		configMgr:        cfgMgr,
		iamService:       iamSvc,
		router:           router,
		providerRegistry: registry,
		pluginManager:    pluginMgr,
	}
}

// ServeHTTP processes the text-to-speech request.
// It uses the iamService's AuthMiddleware for authentication and authorization.
func (h *TextToSpeechProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHandler := h.iamService.AuthMiddleware(http.HandlerFunc(h.handleTextToSpeechLogic))
	authHandler.ServeHTTP(w, r)
}

// handleTextToSpeechLogic contains the core logic after authentication and authorization.
func (h *TextToSpeechProxyHandler) handleTextToSpeechLogic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modelID := chi.URLParam(r, "modelID")

	var ttsReq provider.TextToSpeechRequest
	if err := json.NewDecoder(r.Body).Decode(&ttsReq); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if ttsReq.Model == "" {
		ttsReq.Model = modelID
	} else if ttsReq.Model != modelID {
		http.Error(w, fmt.Sprintf("Model ID in path ('%s') does not match model ID in request body ('%s')", modelID, ttsReq.Model), http.StatusBadRequest)
		return
	}
	if ttsReq.Input == "" {
		http.Error(w, "Input text is required for TTS", http.StatusBadRequest)
		return
	}
	if ttsReq.Voice == "" {
		http.Error(w, "Voice is required for TTS", http.StatusBadRequest)
		return
	}

	h.logger.Info("Received text-to-speech request",
		zap.String("model_id", ttsReq.Model),
		zap.String("voice", ttsReq.Voice),
		zap.String("response_format", ttsReq.ResponseFormat))

	// 1. Route Resolution
	routeCtx := routing.IncomingRequestContext{
		Path:     r.URL.Path,
		Method:   r.Method,
		Headers:  r.Header,
		ModelID:  modelID, // User-facing model ID from path
		Protocol: config.ProtocolHTTPLLM,
	}
	resolvedTarget, err := h.router.ResolveRoute(ctx, routeCtx)
	if err != nil {
		h.logger.Error("Failed to resolve route for TTS", zap.String("model_id", modelID), zap.Error(err))
		http.Error(w, "Route not found or routing error: "+err.Error(), http.StatusNotFound)
		return
	}
	if resolvedTarget.Adapter == nil {
		h.logger.Error("Route resolved but no adapter found for TTS", zap.String("model_id", modelID), zap.String("route_id", resolvedTarget.Route.ID))
		http.Error(w, "Internal server error: adapter not found for resolved route", http.StatusInternalServerError)
		return
	}

	// 2. IAM Check
	principalID, _ := ctx.Value(iam.ContextKeyPrincipalID).(string)
	authInfo := ctx.Value(iam.ContextKeyAuthInfo)

	if principalID == "" {
		h.logger.Warn("No principal found in context for TTS, denying.", zap.String("model_id", modelID), zap.String("route_id", resolvedTarget.Route.ID))
		http.Error(w, "Forbidden: Authentication required.", http.StatusForbidden)
		return
	}

	modelSpecificPermission := config.Permission(fmt.Sprintf("proxy:invoke:texttospeech:%s", modelID))
	generalTTSPermission := config.Permission("proxy:invoke:texttospeech")
	generalProxyPermission := config.Permission("proxy:invoke")

	if !h.iamService.CheckPermission(ctx, principalID, authInfo, modelSpecificPermission) &&
		!h.iamService.CheckPermission(ctx, principalID, authInfo, generalTTSPermission) &&
		!h.iamService.CheckPermission(ctx, principalID, authInfo, generalProxyPermission) {
		h.logger.Warn("Permission denied for TTS",
			zap.String("principal_id", principalID),
			zap.String("model_id", modelID),
			zap.String("route_id", resolvedTarget.Route.ID),
			zap.String("permission_attempted_model", string(modelSpecificPermission)),
			zap.String("permission_attempted_tts", string(generalTTSPermission)),
			zap.String("permission_attempted_proxy", string(generalProxyPermission)))
		http.Error(w, "Forbidden: You do not have permission for TTS.", http.StatusForbidden)
		return
	}
	h.logger.Info("IAM check passed for TTS", zap.String("principal_id", principalID), zap.String("model_id", modelID))

	// Get UpstreamModelName from resolved ModelConfig
	currentFullConfig := h.configMgr.GetCurrentConfig()
	var upstreamModelName string
	var targetModelConfig *config.ModelConfig
	if currentFullConfig != nil {
		for _, mc := range currentFullConfig.Models {
			if mc.ID == resolvedTarget.Target.Ref {
				targetModelConfig = &mc
				upstreamModelName = mc.UpstreamModelName
				break
			}
		}
	}
	if targetModelConfig == nil {
		h.logger.Error("ModelConfig not found for resolved target ref for TTS", zap.String("target_ref", resolvedTarget.Target.Ref), zap.String("model_id", modelID))
		http.Error(w, "Internal server error: Model configuration missing for resolved route", http.StatusInternalServerError)
		return
	}
	// Update ttsReq.Model to the upstream name for the provider
	ttsReq.Model = upstreamModelName

	// 3. Pre-Request Plugin Hooks
	modifiedReqInterface, err := h.pluginManager.ExecutePreRequestHooks(ctx, resolvedTarget.Route, r, ttsReq)
	if err != nil {
		h.logger.Error("Error executing pre-request plugins for TTS", zap.String("model_id", modelID), zap.Error(err))
		http.Error(w, "Plugin error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	finalTTSReq, ok := modifiedReqInterface.(provider.TextToSpeechRequest)
	if !ok {
		h.logger.Error("Pre-request plugin returned unexpected type for TTS request", zap.String("model_id", modelID))
		http.Error(w, "Plugin error: type mismatch after pre-request hooks", http.StatusInternalServerError)
		return
	}

	// 4. Provider Invocation
	// Wrap the ResponseWriter with ResponseTracker to track header state
	tracker := NewResponseTracker(w)

	// Set appropriate Content-Type based on requested format (or provider default).
	// Example: "audio/mpeg" for mp3, "audio/opus", "audio/aac", "audio/flac"
	// Default to "audio/mpeg" if not specified or invalid.
	contentType := "audio/mpeg" // Default
	switch ttsReq.ResponseFormat {
	case "opus":
		contentType = "audio/opus"
	case "aac":
		contentType = "audio/aac"
	case "flac":
		contentType = "audio/flac"
	case "mp3", "": // Default to mp3
		ttsReq.ResponseFormat = "mp3" // Ensure it's set for provider if it was empty
		contentType = "audio/mpeg"
	default:
		h.logger.Warn("Unsupported TTS response format requested, defaulting to mp3", zap.String("requested_format", ttsReq.ResponseFormat))
		ttsReq.ResponseFormat = "mp3"
		contentType = "audio/mpeg"
	}
	tracker.Header().Set("Content-Type", contentType)

	// Add other headers like Content-Disposition if direct download is desired.
	// tracker.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"speech.%s\"", finalTTSReq.ResponseFormat))

	// Note: Post-request plugins that modify the response body are difficult here because the adapter writes directly.
	// Such plugins would need to intercept the io.Writer or the adapter API would need to change.
	// For now, post-request hooks will not be able to modify the audio stream body.

	err = resolvedTarget.Adapter.TextToSpeech(ctx, &finalTTSReq, tracker) // Pass ResponseTracker as io.Writer
	if err != nil {
		h.logger.Error("Error generating speech from provider", zap.Error(err), zap.String("provider_id", resolvedTarget.Adapter.GetConfig().ID))
		// Use ResponseTracker to check if headers have been written
		if !tracker.HeaderWritten() {
			// Headers haven't been written yet, we can send an error response
			http.Error(w, fmt.Sprintf("Failed to generate speech: %v", err), http.StatusInternalServerError)
		}
		// If headers were already sent, we can't change status code, but error is logged.
	}
	// If successful, data is streamed directly to w.
	// Post-request hooks could still run here if they don't modify the body, e.g., for logging/metrics.
	// _, postHookErr := h.pluginManager.ExecutePostRequestHooks(ctx, resolvedTarget.Route, r, nil) // Passing nil as response body
	// if postHookErr != nil {
	//    h.logger.Error("Error executing post-request plugins for TTS (after stream)", zap.Error(postHookErr))
	// }
}

// ResponseTracker wraps http.ResponseWriter to track if headers have been written
type ResponseTracker struct {
	http.ResponseWriter
	headerWritten bool
	statusCode    int
}

// NewResponseTracker creates a new ResponseTracker wrapping the given ResponseWriter
func NewResponseTracker(w http.ResponseWriter) *ResponseTracker {
	return &ResponseTracker{
		ResponseWriter: w,
		headerWritten:  false,
		statusCode:     http.StatusOK, // Default status code
	}
}

// WriteHeader tracks when headers are written and captures the status code
func (rt *ResponseTracker) WriteHeader(code int) {
	if !rt.headerWritten {
		rt.headerWritten = true
		rt.statusCode = code
		rt.ResponseWriter.WriteHeader(code)
	}
}

// Write tracks when data is written (which implicitly writes headers)
func (rt *ResponseTracker) Write(data []byte) (int, error) {
	if !rt.headerWritten {
		rt.headerWritten = true
		rt.statusCode = http.StatusOK // Default when Write is called without WriteHeader
	}
	return rt.ResponseWriter.Write(data)
}

// HeaderWritten returns true if headers have been written to the response
func (rt *ResponseTracker) HeaderWritten() bool {
	return rt.headerWritten
}

// StatusCode returns the status code that was written (or would be written)
func (rt *ResponseTracker) StatusCode() int {
	return rt.statusCode
}

// headersWritten is a helper to check if http.ResponseWriter has written headers
func headersWritten(w http.ResponseWriter) bool {
	if tracker, ok := w.(*ResponseTracker); ok {
		return tracker.HeaderWritten()
	}
	// If it's not a ResponseTracker, we can't reliably determine if headers were written
	// In practice, this should not happen if we properly wrap all ResponseWriters
	return false
}
