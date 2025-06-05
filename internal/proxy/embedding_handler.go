package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam"
	"github.com/openpons/gateway/internal/pluginruntime"
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/routing"
	// "github.com/openpons/gateway/internal/telemetry" // Will be removed if NewNopLogger is replaced
)

// EmbeddingProxyHandler handles requests for text embeddings.
type EmbeddingProxyHandler struct {
	logger           *zap.Logger
	configMgr        config.ManagerInterface
	iamService       iam.ServiceInterface // For AuthN/AuthZ
	router           routing.RouterInterface
	providerRegistry provider.RegistryInterface
	pluginManager    pluginruntime.ManagerInterface
}

// NewEmbeddingProxyHandler creates a new handler for embedding requests.
func NewEmbeddingProxyHandler(
	cfgMgr config.ManagerInterface,
	iamSvc iam.ServiceInterface,
	router routing.RouterInterface,
	registry provider.RegistryInterface,
	pluginMgr pluginruntime.ManagerInterface,
	log *zap.Logger,
) *EmbeddingProxyHandler {
	if log == nil {
		log = zap.NewNop() // Use zap.NewNop()
	}
	return &EmbeddingProxyHandler{
		logger:           log.Named("embedding-proxy"),
		configMgr:        cfgMgr,
		iamService:       iamSvc,
		router:           router,
		providerRegistry: registry,
		pluginManager:    pluginMgr,
	}
}

// ServeHTTP processes the embedding request.
// It uses the iamService's AuthMiddleware for authentication and authorization.
func (h *EmbeddingProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHandler := h.iamService.AuthMiddleware(http.HandlerFunc(h.handleEmbeddingLogic))
	authHandler.ServeHTTP(w, r)
}

// handleEmbeddingLogic contains the core logic after authentication and authorization.
func (h *EmbeddingProxyHandler) handleEmbeddingLogic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modelID := chi.URLParam(r, "modelID") // Extract modelID from path

	var embedReq provider.EmbeddingRequest
	if err := json.NewDecoder(r.Body).Decode(&embedReq); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Ensure the model ID from path is used if not in body, or validate consistency
	if embedReq.Model == "" {
		embedReq.Model = modelID
	} else if embedReq.Model != modelID {
		http.Error(w, fmt.Sprintf("Model ID in path ('%s') does not match model ID in request body ('%s')", modelID, embedReq.Model), http.StatusBadRequest)
		return
	}

	h.logger.Info("Received embedding request", zap.String("model_id", modelID), zap.Any("input_type", fmt.Sprintf("%T", embedReq.Input)))

	// 1. Route Matching
	reqCtx := routing.IncomingRequestContext{
		Path:     r.URL.Path,
		Method:   r.Method,
		Headers:  r.Header,
		ModelID:  modelID,                // User-facing model ID
		Protocol: config.ProtocolHTTPLLM, // Assuming embeddings are via LLM protocol
	}

	resolvedTarget, err := h.router.ResolveRoute(ctx, reqCtx)
	if err != nil {
		h.logger.Error("Failed to resolve route for embedding request", zap.Error(err), zap.String("model_id", modelID))
		// Distinguish between "not found" and other errors if ResolveRoute provides that
		if strings.Contains(err.Error(), "no matching route found") { // Basic check
			http.Error(w, "No route found for the request: "+err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, "Error resolving route: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if resolvedTarget == nil || resolvedTarget.Adapter == nil || resolvedTarget.Target == nil { // Should be caught by error from ResolveRoute
		h.logger.Error("Route resolution returned nil target or adapter", zap.String("model_id", modelID))
		http.Error(w, "Internal server error: route resolution failed", http.StatusInternalServerError)
		return
	}
	h.logger.Debug("Route resolved for embedding request",
		zap.String("route_id", resolvedTarget.Route.ID),
		zap.String("route_name", resolvedTarget.Route.Name),
		zap.String("target_ref", resolvedTarget.Target.Ref),
		zap.String("provider_id", resolvedTarget.Adapter.GetConfig().ID),
	)

	// 2. IAM Check
	principalID, _ := ctx.Value(iam.ContextKeyPrincipalID).(string) // Assuming AuthMiddleware sets this
	authInfo := ctx.Value(iam.ContextKeyAuthInfo)                   // And this, which could be *iam.APIKey or *iam.GatewayJWTClaims

	// If AuthMiddleware did not set a principal, and the route is not public,
	// Authorize should ideally handle this. For now, we proceed if principalID is found.
	// A more robust check might be needed if some proxy routes can be public.
	// For now, assume all proxy routes require some form of valid authentication.
	if principalID == "" {
		h.logger.Warn("No principal found in context for embedding request, denying.", zap.String("model_id", modelID), zap.String("route_id", resolvedTarget.Route.ID))
		http.Error(w, "Forbidden: Authentication required.", http.StatusForbidden) // Or 401 if preferred before Authz
		return
	}

	// The Authorize method in iam.Service needs to be implemented to use principalID and authInfo correctly.
	// Try model-specific permission first, then a general embedding permission, then a general proxy permission.
	modelSpecificPermission := config.Permission("proxy:embeddings:invoke:" + modelID)
	generalEmbeddingPermission := config.Permission("proxy:embeddings:invoke")
	generalProxyPermission := config.Permission("proxy:invoke")

	if !h.iamService.CheckPermission(ctx, principalID, authInfo, modelSpecificPermission) &&
		!h.iamService.CheckPermission(ctx, principalID, authInfo, generalEmbeddingPermission) &&
		!h.iamService.CheckPermission(ctx, principalID, authInfo, generalProxyPermission) {
		h.logger.Warn("Authorization failed for embedding request",
			zap.String("principal_id", principalID),
			zap.String("model_id", modelID),
			zap.String("route_id", resolvedTarget.Route.ID),
			zap.String("permission_attempted_model", string(modelSpecificPermission)),
			zap.String("permission_attempted_embedding", string(generalEmbeddingPermission)),
			zap.String("permission_attempted_proxy", string(generalProxyPermission)))
		http.Error(w, "Forbidden: You do not have permission to perform this action.", http.StatusForbidden)
		return
	}
	h.logger.Debug("Authorization successful for embedding request",
		zap.String("principal_id", principalID),
		zap.String("model_id", modelID))
	// Not logging specific permission granted to avoid log verbosity if multiple were checked.

	// 3. Pre-Request Plugins
	// The request body for plugins could be the raw http.Request or the parsed provider.EmbeddingRequest.
	// Let's assume plugins operate on the provider-specific request struct for now.
	modifiedEmbedReqInterface, err := h.pluginManager.ExecutePreRequestHooks(ctx, resolvedTarget.Route, r, embedReq)
	if err != nil {
		h.logger.Error("Error executing pre-request plugins for embedding request",
			zap.Error(err),
			zap.String("route_id", resolvedTarget.Route.ID),
			zap.String("model_id", modelID))
		http.Error(w, fmt.Sprintf("Error in pre-request plugin: %v", err), http.StatusInternalServerError)
		return
	}
	if modifiedEmbedReqInterface != nil {
		var ok bool
		embedReq, ok = modifiedEmbedReqInterface.(provider.EmbeddingRequest)
		if !ok {
			h.logger.Error("Pre-request plugin returned unexpected type for embedding request",
				zap.String("route_id", resolvedTarget.Route.ID),
				zap.String("model_id", modelID),
				zap.String("type", fmt.Sprintf("%T", modifiedEmbedReqInterface)))
			http.Error(w, "Internal server error: plugin type mismatch", http.StatusInternalServerError)
			return
		}
	}

	// 4. Target Selection & Provider Invocation
	// The route has been resolved to a specific target (ModelConfig.ID via resolvedTarget.Target.Ref)
	// and a specific provider adapter (resolvedTarget.Adapter).
	// Now, we prepare the request for that provider using the upstream model name.

	// Find the ModelConfig to get the ProviderID
	// This logic might be part of the routing.Router or a dedicated service.
	// For now, a simplified direct lookup:
	// var targetProviderID string // Now derived from selectedTarget
	// var upstreamModelName string // Now derived from selectedTarget

	// The selectedTarget.Ref is the ModelConfig.ID.
	// The adapter is already resolved by ResolveRoute.
	// We need the UpstreamModelName from the ModelConfig.
	currentConfig := h.configMgr.GetCurrentConfig()
	if currentConfig == nil {
		h.logger.Error("Runtime configuration is not available for embedding handler")
		http.Error(w, "System configuration error", http.StatusInternalServerError)
		return
	}
	var upstreamModelName string
	foundModelCfg := false
	for _, mc := range currentConfig.Models {
		if mc.ID == resolvedTarget.Target.Ref {
			upstreamModelName = mc.UpstreamModelName
			foundModelCfg = true
			break
		}
	}
	if !foundModelCfg {
		h.logger.Error("Upstream model name not found for target ref", zap.String("target_ref", resolvedTarget.Target.Ref))
		http.Error(w, fmt.Sprintf("Internal configuration error: upstream model for '%s' not found", resolvedTarget.Target.Ref), http.StatusInternalServerError)
		return
	}

	// Use the upstream model name for the provider request
	embedReq.Model = upstreamModelName

	adapter := resolvedTarget.Adapter // Use the adapter from resolvedTarget
	// The 'err' variable from h.router.ResolveRoute is already checked.
	// The adapter itself is checked by ResolveRoute returning an error if it can't find one.
	// So, direct error check on adapter here might be redundant if ResolveRoute is robust.
	// However, keeping a nil check for safety.
	if adapter == nil {
		h.logger.Error("Adapter from resolved target is nil", zap.String("model_id", modelID), zap.String("target_ref", resolvedTarget.Target.Ref))
		http.Error(w, "Internal server error: failed to get provider adapter", http.StatusInternalServerError)
		return
	}

	embedResp, err := adapter.GenerateEmbedding(ctx, &embedReq)
	if err != nil {
		h.logger.Error("Error generating embedding from provider", zap.Error(err), zap.String("provider_id", adapter.GetConfig().ID))
		statusCode, clientMsg := mapProviderErrorToHTTPStatus(err, http.StatusInternalServerError, "Failed to generate embedding")
		http.Error(w, clientMsg, statusCode)
		return
	}

	// 5. Post-Request Plugins
	finalEmbedResp := embedResp // Start with the original response
	if h.pluginManager != nil { // Check if pluginManager is initialized
		modifiedEmbedRespInterface, pluginErr := h.pluginManager.ExecutePostRequestHooks(ctx, resolvedTarget.Route, r, embedResp)
		if pluginErr != nil {
			h.logger.Error("Error executing post-request plugins for embedding response",
				zap.Error(pluginErr),
				zap.String("route_id", resolvedTarget.Route.ID),
				zap.String("model_id", modelID))
			// Decide on error handling:
			// Option 1: Return error to client, potentially masking successful provider response.
			// http.Error(w, fmt.Sprintf("Error in post-request plugin: %v", pluginErr), http.StatusInternalServerError)
			// return
			// Option 2: Log plugin error and proceed with original/partially modified response.
			// For now, let's log and proceed with the response we have (which might be original if plugin failed early).
			// If plugins are critical, returning an error might be better.
		} else if modifiedEmbedRespInterface != nil {
			var ok bool
			finalEmbedResp, ok = modifiedEmbedRespInterface.(*provider.EmbeddingResponse)
			if !ok {
				h.logger.Error("Post-request plugin returned unexpected type for embedding response",
					zap.String("route_id", resolvedTarget.Route.ID),
					zap.String("model_id", modelID),
					zap.String("type", fmt.Sprintf("%T", modifiedEmbedRespInterface)))
				// If type assertion fails, proceed with finalEmbedResp which is still original embedResp
				// or return an error:
				// http.Error(w, "Internal server error: plugin type mismatch post-request", http.StatusInternalServerError)
				// return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(finalEmbedResp); err != nil {
		h.logger.Error("Failed to write embedding response", zap.Error(err))
		// http.Error already sent if possible, otherwise client connection might be gone
	}
}
