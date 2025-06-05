package proxy

import (
	"encoding/json"
	"fmt"
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

// ToolProxyHandler handles requests for MCP/A2A tool invocations.
type ToolProxyHandler struct {
	logger           *zap.Logger
	configMgr        config.ManagerInterface
	iamService       iam.ServiceInterface
	router           routing.RouterInterface // For finding routes to tool providers
	providerRegistry provider.RegistryInterface
	pluginManager    pluginruntime.ManagerInterface
}

// NewToolProxyHandler creates a new handler for tool invocation requests.
func NewToolProxyHandler(
	cfgMgr config.ManagerInterface,
	iamSvc iam.ServiceInterface,
	router routing.RouterInterface,
	registry provider.RegistryInterface,
	pluginMgr pluginruntime.ManagerInterface,
	log *zap.Logger,
) *ToolProxyHandler {
	if log == nil {
		log = zap.NewNop() // Use zap.NewNop()
	}
	return &ToolProxyHandler{
		logger:           log.Named("tool-proxy"),
		configMgr:        cfgMgr,
		iamService:       iamSvc,
		router:           router,
		providerRegistry: registry,
		pluginManager:    pluginMgr,
	}
}

// ServeHTTP processes the tool invocation request.
// It uses the iamService's AuthMiddleware for authentication and authorization.
func (h *ToolProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHandler := h.iamService.AuthMiddleware(http.HandlerFunc(h.handleToolInvocationLogic))
	authHandler.ServeHTTP(w, r)
}

// handleToolInvocationLogic contains the core logic after authentication and authorization.
func (h *ToolProxyHandler) handleToolInvocationLogic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	toolID := chi.URLParam(r, "toolID") // User-facing ToolConfig.ID

	var toolReq provider.ToolInvocationRequest
	if err := json.NewDecoder(r.Body).Decode(&toolReq); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// ToolName in request body might be more specific than toolID from path,
	// or toolID from path is the primary identifier.
	if toolReq.ToolName == "" {
		toolReq.ToolName = toolID // Use toolID from path if not in body
	} else if toolReq.ToolName != toolID {
		// This could be an error, or toolID is a general category and ToolName is specific.
		// For now, assume toolID from path is the key for finding the ToolConfig.
		h.logger.Info("Tool name in body differs from toolID in path",
			zap.String("path_tool_id", toolID),
			zap.String("body_tool_name", toolReq.ToolName))
		// Decision: For now, let provider adapter handle if ToolName matters beyond what toolID implies.
	}

	h.logger.Info("Received tool invocation request",
		zap.String("tool_id", toolID),
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method))

	// 1. Route Resolution
	routeCtx := routing.IncomingRequestContext{
		Path:     r.URL.Path, // Or a more specific path if tool invocations have sub-paths
		Method:   r.Method,
		Headers:  r.Header,
		ToolID:   toolID,
		Protocol: config.ProtocolMCPTool, // Assuming MCP for now, could be A2A
	}
	resolvedTarget, err := h.router.ResolveRoute(ctx, routeCtx)
	if err != nil {
		h.logger.Error("Failed to resolve route for tool invocation", zap.String("tool_id", toolID), zap.Error(err))
		http.Error(w, "Tool route not found or routing error: "+err.Error(), http.StatusNotFound)
		return
	}
	if resolvedTarget.Adapter == nil {
		h.logger.Error("Route resolved but no adapter found", zap.String("tool_id", toolID), zap.String("route_id", resolvedTarget.Route.ID))
		http.Error(w, "Internal server error: adapter not found for resolved route", http.StatusInternalServerError)
		return
	}
	adapterProviderCfg := resolvedTarget.Adapter.GetConfig()
	if adapterProviderCfg.Type != config.ProviderTypeToolServer && adapterProviderCfg.Type != config.ProviderTypeAgentPlatform {
		errMsg := fmt.Sprintf("Resolved provider %s (type %s) does not support tool invocations", adapterProviderCfg.ID, adapterProviderCfg.Type) // Use adapterProviderCfg.ID
		h.logger.Error(errMsg, zap.String("tool_id", toolID))
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	// 2. IAM Check
	principalIDVal := ctx.Value(iam.ContextKeyPrincipalID)
	principalID, _ := principalIDVal.(string) // Will be empty if not authenticated or not string
	authInfo := ctx.Value(iam.ContextKeyAuthInfo)
	// Define required permissions
	toolSpecificPermission := config.Permission(fmt.Sprintf("proxy:invoke:tool:%s", toolID))
	generalToolPermission := config.Permission("proxy:invoke:tool")
	generalProxyPermission := config.Permission("proxy:invoke")

	if principalID == "" { // Should be caught by AuthMiddleware if auth is mandatory
		h.logger.Warn("No principal found in context for tool invocation, denying.", zap.String("tool_id", toolID), zap.String("route_id", resolvedTarget.Route.ID))
		http.Error(w, "Forbidden: Authentication required.", http.StatusForbidden)
		return
	}

	if !h.iamService.CheckPermission(ctx, principalID, authInfo, toolSpecificPermission) &&
		!h.iamService.CheckPermission(ctx, principalID, authInfo, generalToolPermission) &&
		!h.iamService.CheckPermission(ctx, principalID, authInfo, generalProxyPermission) {
		h.logger.Warn("Permission denied for tool invocation",
			zap.String("principal_id", principalID),
			zap.String("tool_id", toolID),
			zap.String("route_id", resolvedTarget.Route.ID),
			zap.String("permission_attempted_specific", string(toolSpecificPermission)),
			zap.String("permission_attempted_general_tool", string(generalToolPermission)),
			zap.String("permission_attempted_general_proxy", string(generalProxyPermission)))
		http.Error(w, "Forbidden: You do not have permission to invoke this tool.", http.StatusForbidden)
		return
	}
	h.logger.Info("IAM check passed for tool invocation", zap.String("principal_id", principalID), zap.String("tool_id", toolID))

	// Ensure the ToolName in the request matches the resolved target's reference if it's an ID.
	// The resolvedTarget.Target.Ref should be the ToolConfig.ID.
	// We need to get the UpstreamToolName from the ToolConfig.
	currentFullConfig := h.configMgr.GetCurrentConfig()
	var upstreamToolName string
	var targetToolConfig *config.ToolConfig

	if currentFullConfig != nil {
		for _, tc := range currentFullConfig.Tools {
			if tc.ID == resolvedTarget.Target.Ref { // resolvedTarget.Target.Ref is the ToolConfig ID
				targetToolConfig = &tc
				upstreamToolName = tc.UpstreamToolName
				break
			}
		}
	}
	if targetToolConfig == nil {
		h.logger.Error("ToolConfig not found for resolved target ref", zap.String("target_ref", resolvedTarget.Target.Ref), zap.String("tool_id", toolID))
		http.Error(w, "Internal server error: Tool configuration missing for resolved route", http.StatusInternalServerError)
		return
	}
	// Use the upstream name for the actual provider call.
	toolReq.ToolName = upstreamToolName

	// 3. Pre-Request Plugin Hooks
	modifiedReqInterface, err := h.pluginManager.ExecutePreRequestHooks(ctx, resolvedTarget.Route, r, toolReq)
	if err != nil {
		h.logger.Error("Error executing pre-request plugins for tool invocation", zap.String("tool_id", toolID), zap.Error(err))
		http.Error(w, "Plugin error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	finalToolReq, ok := modifiedReqInterface.(provider.ToolInvocationRequest)
	if !ok {
		h.logger.Error("Pre-request plugin returned unexpected type for tool request", zap.String("tool_id", toolID))
		http.Error(w, "Plugin error: type mismatch after pre-request hooks", http.StatusInternalServerError)
		return
	}

	// 4. Decide InvokeTool vs StreamInvokeTool
	isStreamingRequest := targetToolConfig.SupportsStreaming
	// Additionally, one might check request headers like "Accept: text/event-stream" or a specific field in toolReq
	// For now, ToolConfig.SupportsStreaming is the primary driver.

	var toolRespInterface interface{}
	var invokeErr error

	if isStreamingRequest {
		h.logger.Info("Streaming tool invocation selected",
			zap.String("tool_id", toolID),
			zap.String("tool_name_upstream", upstreamToolName),
			zap.String("provider_id", resolvedTarget.Adapter.GetConfig().ID))

		// 1. Set response headers for streaming
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK) // Send headers immediately

		// 2. Create request and response channels for StreamInvokeTool
		requestStream := make(chan *provider.ToolInvocationStreamChunk)
		responseStream := make(chan *provider.ToolInvocationStreamChunk)

		// 3. Handle client-side request streaming
		go func() {
			defer close(requestStream)
			// For now, send the initial request as a single chunk
			// In a full implementation, this could handle NDJSON input for streaming requests
			// Marshal the tool request to send as payload
			reqPayload, err := json.Marshal(finalToolReq)
			if err != nil {
				h.logger.Error("Failed to marshal tool request for streaming", zap.Error(err))
				return
			}

			initialChunk := &provider.ToolInvocationStreamChunk{
				Payload: reqPayload,
				IsLast:  true, // Single chunk for now
			}

			select {
			case requestStream <- initialChunk:
			case <-ctx.Done():
				return
			}
		}()

		// 4. Call StreamInvokeTool in a goroutine
		go func() {
			defer close(responseStream)
			errStream := resolvedTarget.Adapter.StreamInvokeTool(ctx, requestStream, responseStream)
			if errStream != nil {
				h.logger.Error("Error during StreamInvokeTool execution", zap.Error(errStream))
				// Send error chunk before closing
				errorChunk := &provider.ToolInvocationStreamChunk{
					Error: &provider.ToolError{
						Type:    "AdapterError",
						Message: errStream.Error(),
					},
					IsLast: true,
				}
				select {
				case responseStream <- errorChunk:
				case <-ctx.Done():
				}
			}
		}()

		// 5. Read from responseStream and write to http.ResponseWriter
		flusher, ok := w.(http.Flusher)
		if !ok {
			invokeErr = fmt.Errorf("streaming unsupported: ResponseWriter does not implement http.Flusher")
			// Fall through to error handling below
		} else {
			for chunk := range responseStream {
				// Marshal chunk to JSON as NDJSON
				if chunkBytes, err := json.Marshal(chunk); err == nil {
					w.Write(chunkBytes)
					w.Write([]byte("\n"))
					flusher.Flush()
				} else {
					h.logger.Error("Failed to marshal streaming chunk", zap.Error(err))
					// Continue processing other chunks
				}

				// Check for completion or error
				if chunk.Error != nil || chunk.IsLast {
					break
				}
			}

			// Streaming handled successfully, return early
			h.logger.Info("Successfully completed streaming tool invocation", zap.String("tool_id", toolID))
			return
		}
	} else {
		h.logger.Info("Unary tool invocation selected",
			zap.String("tool_id", toolID),
			zap.String("tool_name_upstream", upstreamToolName),
			zap.String("provider_id", resolvedTarget.Adapter.GetConfig().ID)) // Corrected
		toolResp, err := resolvedTarget.Adapter.InvokeTool(ctx, &finalToolReq) // Pass address
		if err != nil {
			invokeErr = err
		} else {
			toolRespInterface = toolResp
		}
	}

	if invokeErr != nil {
		h.logger.Error("Error invoking tool via provider adapter",
			zap.String("tool_id", toolID),
			zap.String("provider_id", resolvedTarget.Adapter.GetConfig().ID), // Corrected
			zap.Error(invokeErr))
		statusCode, clientMsg := mapProviderErrorToHTTPStatus(invokeErr, http.StatusInternalServerError, "Failed to invoke tool")
		http.Error(w, clientMsg, statusCode)
		return
	}

	// 5. Post-Request Plugin Hooks
	finalRespInterface, err := h.pluginManager.ExecutePostRequestHooks(ctx, resolvedTarget.Route, r, toolRespInterface)
	if err != nil {
		h.logger.Error("Error executing post-request plugins for tool invocation", zap.String("tool_id", toolID), zap.Error(err))
		http.Error(w, "Plugin error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 6. Write Response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(finalRespInterface); err != nil {
		h.logger.Error("Failed to write tool invocation response", zap.String("tool_id", toolID), zap.Error(err))
		// Response might have already been partially written or headers sent
	}
	h.logger.Info("Successfully processed tool invocation request", zap.String("tool_id", toolID))
}
