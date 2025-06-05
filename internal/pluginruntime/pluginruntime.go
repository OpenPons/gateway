// Package pluginruntime is responsible for loading, managing, and executing
// out-of-process plugins (e.g., via Hashicorp go-plugin or Envoy ext_proc).
// It handles plugin discovery, lifecycle, sandboxing, and communication.
package pluginruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"sort" // Added import for sorting
	"sync"
	"time" // Added for retry delay

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/telemetry"
	"github.com/openpons/gateway/internal/xds"
	extprocpb "github.com/openpons/gateway/pkg/api/v1alpha1/extproc" // Generated proto for PluginHookService
	gwplugin "github.com/openpons/gateway/pkg/plugin"                // Alias for our plugin SDK package
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	pluginLaunchMaxRetries = 2 // Total 3 attempts
	pluginLaunchRetryDelay = 200 * time.Millisecond
)

// PluginManager manages the lifecycle of all registered plugins.
type PluginManager struct {
	mu              sync.RWMutex
	clients         map[string]*plugin.Client // pluginID -> go-plugin client
	plugins         []config.PluginDefinition // List of available plugin definitions
	pluginHealth    map[string]bool           // pluginID -> isHealthy
	healthCheckCtx  context.Context           // Context for health checking goroutine
	healthCheckStop func()                    // Function to stop health checking goroutine
	configManager   config.ManagerInterface   // To get plugin configurations and subscribe to updates
	configWatchCtx  context.Context           // Context for config watching goroutine
	configWatchStop func()                    // Function to stop config watching goroutine

	// testHookClients is used for testing to inject mock clients.
	testHookClients map[string]gwplugin.PluginHookService
}

// ManagerInterface defines the methods proxy handlers (and other components)
// need from a PluginManager. This allows for easier mocking in tests.
type ManagerInterface interface {
	ExecutePreRequestHooks(ctx context.Context, route *config.RouteConfig, httpRequest *http.Request, providerRequest interface{}) (interface{}, error)
	ExecutePostRequestHooks(ctx context.Context, route *config.RouteConfig, httpRequest *http.Request, providerResponse interface{}) (interface{}, error)
	GetPluginClient(pluginID string) (gwplugin.PluginHookService, error)
	Shutdown() // Added Shutdown method
}

// NewPluginManager creates a new PluginManager.
func NewPluginManager(initialPluginDefs []config.PluginDefinition, cm config.ManagerInterface) (*PluginManager, error) {
	pm := &PluginManager{
		clients:       make(map[string]*plugin.Client),
		plugins:       initialPluginDefs, // Initial set of plugins
		pluginHealth:  make(map[string]bool),
		configManager: cm,
	}

	pm.healthCheckCtx, pm.healthCheckStop = context.WithCancel(context.Background())
	go pm.periodicHealthChecker(pm.healthCheckCtx)

	if cm != nil {
		pm.configWatchCtx, pm.configWatchStop = context.WithCancel(context.Background())
		go pm.watchConfigChanges(pm.configWatchCtx)
	}

	return pm, nil
}

// watchConfigChanges listens for updates from the ConfigManager and reconciles plugins.
func (pm *PluginManager) watchConfigChanges(ctx context.Context) {
	if pm.configManager == nil {
		log.Println("PluginManager: ConfigManager is nil, cannot watch for config changes.")
		return
	}

	configChan := pm.configManager.Subscribe()
	log.Println("PluginManager: Subscribed to configuration updates.")

	for {
		select {
		case newRuntimeConfig, ok := <-configChan:
			if !ok {
				log.Println("PluginManager: Configuration channel closed. Stopping watch.")
				return
			}
			if newRuntimeConfig == nil {
				log.Println("PluginManager: Received nil runtime config, skipping plugin reconciliation.")
				continue
			}
			log.Println("PluginManager: Received new runtime configuration, reconciling plugins.")
			pm.reconcilePlugins(newRuntimeConfig.Plugins)
		case <-ctx.Done():
			log.Println("PluginManager: Config watch context cancelled. Stopping watch.")
			// Unsubscribe logic might be needed if ConfigManager supports it
			return
		}
	}
}

// reconcilePlugins updates the plugin manager's state based on the new plugin definitions.
func (pm *PluginManager) reconcilePlugins(newPluginDefs []config.PluginDefinition) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	currentDefsMap := make(map[string]config.PluginDefinition)
	for _, p := range pm.plugins {
		currentDefsMap[p.ID] = p
	}

	newDefsMap := make(map[string]config.PluginDefinition)
	for _, p := range newPluginDefs {
		newDefsMap[p.ID] = p
	}

	// Identify plugins to stop or update
	for id, client := range pm.clients {
		newDef, existsInNew := newDefsMap[id]
		currentDef, existsInCurrent := currentDefsMap[id] // Should always exist if in pm.clients

		if !existsInNew || !newDef.Enabled || (existsInCurrent && pluginDefinitionChanged(currentDef, newDef)) {
			log.Printf("PluginManager: Stopping plugin %s (removed, disabled, or definition changed).", id)
			client.Kill()
			delete(pm.clients, id)
			delete(pm.pluginHealth, id)
		}
	}

	// Update the internal list of plugin definitions
	pm.plugins = newPluginDefs

	// New or re-enabled plugins will be started on-demand by GetPluginClient.
	// If proactive starting is desired, it could be added here for plugins
	// that are in newPluginDefs, enabled, and not currently in pm.clients.
	log.Printf("PluginManager: Plugin reconciliation complete. Active definitions: %d", len(pm.plugins))
}

// pluginDefinitionChanged checks if key fields of a plugin definition have changed.
func pluginDefinitionChanged(oldDef, newDef config.PluginDefinition) bool {
	// Compare relevant fields that would require a restart, e.g., ExecutablePath
	if oldDef.ExecutablePath != newDef.ExecutablePath {
		return true
	}
	if oldDef.Enabled != newDef.Enabled { // Though reconcilePlugins handles Enabled separately
		return true
	}
	// Add other critical fields if necessary
	return false
}

// periodicHealthChecker runs health checks on plugins at a defined interval.
func (pm *PluginManager) periodicHealthChecker(ctx context.Context) {
	healthCheckInterval := 30 * time.Second // Default interval

	if pm.configManager != nil {
		currentConfig := pm.configManager.GetCurrentConfig()
		if currentConfig != nil && currentConfig.Settings.PluginHealthCheckIntervalSeconds > 0 {
			healthCheckInterval = time.Duration(currentConfig.Settings.PluginHealthCheckIntervalSeconds) * time.Second
		} else if currentConfig != nil && currentConfig.Settings.PluginHealthCheckIntervalSeconds <= 0 {
			// Log if explicitly set to an invalid value, but still use default.
			// If it's 0 because it's omitted from config, it's fine, default will be used.
			if currentConfig.Settings.PluginHealthCheckIntervalSeconds < 0 { // Only log for negative, 0 is like "use default"
				log.Printf("PluginManager: Invalid PluginHealthCheckIntervalSeconds (%d) in config, using default %v", currentConfig.Settings.PluginHealthCheckIntervalSeconds, 30*time.Second)
			}
			// Ensure healthCheckInterval remains the default 30s if PluginHealthCheckIntervalSeconds is 0 or negative
			healthCheckInterval = 30 * time.Second
		}
		// If currentConfig is nil (e.g., not loaded yet), healthCheckInterval remains the default.
	} else {
		log.Printf("PluginManager: ConfigManager is nil, using default health check interval %v", healthCheckInterval)
	}

	log.Printf("PluginManager: Health check interval set to %v", healthCheckInterval)
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	log.Println("Plugin health checker started.")

	for {
		select {
		case <-ticker.C:
			pm.checkAllPluginsHealth()
		case <-ctx.Done():
			log.Println("Plugin health checker stopping.")
			return
		}
	}
}

// checkAllPluginsHealth iterates over active plugins and performs health checks.
func (pm *PluginManager) checkAllPluginsHealth() {
	pm.mu.RLock()
	pluginDefs := make([]config.PluginDefinition, len(pm.plugins))
	copy(pluginDefs, pm.plugins)
	pm.mu.RUnlock()

	for _, pDef := range pluginDefs {
		if !pDef.Enabled {
			pm.mu.Lock()
			delete(pm.pluginHealth, pDef.ID) // Remove health status for disabled plugins
			pm.mu.Unlock()
			continue
		}

		// Get client without triggering a new launch if not running,
		// but need to handle if it's not in pm.clients map yet or has exited.
		pm.mu.RLock()
		client, clientExists := pm.clients[pDef.ID]
		pm.mu.RUnlock()

		if !clientExists || client.Exited() {
			// Plugin is not running or has exited. Mark as unhealthy.
			// GetPluginClient will attempt to relaunch on next actual use.
			pm.mu.Lock()
			pm.pluginHealth[pDef.ID] = false
			pm.mu.Unlock()
			log.Printf("Plugin %s is not running or has exited. Marked as unhealthy.", pDef.ID)
			continue
		}

		// Dispense the plugin service
		// Note: dispensePlugin has its own retry logic.
		pluginService, err := pm.dispensePlugin(client, pDef.ID)
		if err != nil {
			log.Printf("Error dispensing plugin %s for health check: %v", pDef.ID, err)
			pm.mu.Lock()
			pm.pluginHealth[pDef.ID] = false
			pm.mu.Unlock()
			continue
		}
		_ = pluginService // Acknowledge usage until HealthCheck RPC is implemented

		healthCheckCallCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // 5-second timeout for health check
		defer cancel()
		_ = healthCheckCallCtx // Acknowledge usage until HealthCheck RPC is implemented

		// Assuming gwplugin.HealthCheckRequest and gwplugin.HealthCheckResponse types exist,
		// and pluginService has a HealthCheck method.
		// Example: healthResp, err := pluginService.HealthCheck(healthCheckCallCtx, &gwplugin.HealthCheckRequest{})
		// For this to compile, these types and method must be defined in pkg/plugin and its proto.
		// Let's use extprocpb for now if HealthCheck is part of that service, or assume gwplugin.
		// The extprocpb.PluginHookService does not currently define HealthCheck.
		// We will assume it's added to gwplugin.PluginHookService.

		// Placeholder for the actual call structure until gwplugin.PluginHookService is updated.
		// This code will not compile until the interface and types are defined.
		// For demonstration, let's simulate a call and response structure.
		// Replace this with actual call once `gwplugin.PluginHookService` has `HealthCheck`.
		var isHealthy bool
		var healthStatusString string

		// Simulated call - replace with actual:
		// healthReq := &gwplugin.HealthCheckRequest{} // Assuming this type will exist
		// healthResp, err := pluginService.HealthCheck(healthCheckCallCtx, healthReq)

		// TEMPORARY SIMULATION until HealthCheck RPC is defined in gwplugin:
		// To make this section runnable for now, we'll keep a simulated success.
		// The real implementation depends on the HealthCheck RPC definition.
		err = nil                    // Simulate no error for now
		simulatedStatus := "SERVING" // Simulate a healthy status string

		if err != nil {
			log.Printf("Health check RPC failed for plugin %s: %v", pDef.ID, err)
			isHealthy = false
			healthStatusString = "rpc_error"
		} else {
			// Assuming healthResp.GetStatus() returns a string like "SERVING", "NOT_SERVING", etc.
			// Or healthResp.IsHealthy bool field.
			// Example: status := healthResp.GetStatus()
			// isHealthy = (status == "SERVING") // Adjust based on actual response structure

			// Using simulated status for now:
			healthStatusString = simulatedStatus
			isHealthy = (healthStatusString == "SERVING")
		}

		pm.mu.Lock()
		pm.pluginHealth[pDef.ID] = isHealthy
		pm.mu.Unlock()

		if !isHealthy {
			log.Printf("Plugin %s reported unhealthy (status: %s).", pDef.ID, healthStatusString)
		} else {
			log.Printf("Plugin %s is healthy (status: %s).", pDef.ID, healthStatusString)
		}
	}
}

// IsPluginHealthy returns the last known health status of a plugin.
// This could be used by routing logic or admin APIs.
func (pm *PluginManager) IsPluginHealthy(pluginID string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	isHealthy, exists := pm.pluginHealth[pluginID]
	if !exists {
		return false // If no health status recorded, assume not healthy or not managed.
	}
	return isHealthy
}

// GetPluginClient returns a gRPC client for the specified pluginID.
// It launches the plugin if it's not already running.
func (pm *PluginManager) GetPluginClient(pluginID string) (gwplugin.PluginHookService, error) {
	// Test seam: Check if a mock client is provided for this pluginID
	if pm.testHookClients != nil {
		if mockClient, ok := pm.testHookClients[pluginID]; ok {
			return mockClient, nil
		}
	}

	pm.mu.Lock() // Lock for checking and potentially creating client

	client, exists := pm.clients[pluginID]
	if exists && !client.Exited() {
		pm.mu.Unlock()
		return pm.dispensePlugin(client, pluginID)
	}
	// If client exited, remove it to relaunch
	if exists && client.Exited() {
		log.Printf("Plugin %s had exited, will attempt to relaunch.", pluginID)
		delete(pm.clients, pluginID)
	}
	pm.mu.Unlock() // Unlock before potentially long-running plugin launch

	// Find plugin definition
	var pluginDef *config.PluginDefinition
	for _, p := range pm.plugins {
		if p.ID == pluginID && p.Enabled { // Check if plugin is enabled
			pluginDef = &p
			break
		}
	}

	if pluginDef == nil {
		return nil, fmt.Errorf("plugin %s not found or not enabled", pluginID)
	}
	if pluginDef.ExecutablePath == "" {
		return nil, fmt.Errorf("executable path for plugin %s is not defined", pluginID)
	}

	// Launch the plugin
	var pluginLogger hclog.Logger
	if telemetry.Logger != nil {
		// Adapt telemetry.Logger (zap) to hclog.Logger
		// Assuming xds.NewHCLogAdapter is suitable or a similar one is created in telemetry or here.
		// For now, let's assume xds.NewHCLogAdapter can be used.
		// If xds package is not appropriate to import, this adapter logic should be moved/duplicated.
		pluginLogger = xds.NewHCLogAdapter(telemetry.Logger.Named("plugin-"+pluginID), "plugin-"+pluginID)
	} else {
		// Fallback if telemetry.Logger is not initialized
		pluginLogger = hclog.New(&hclog.LoggerOptions{
			Name:  "plugin-" + pluginID,
			Level: hclog.Info, // Default level
		})
	}

	newClient := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  gwplugin.Handshake, // Use HandshakeConfig from our pkg/plugin
		Plugins:          gwplugin.PluginMap, // PluginMap from our pkg/plugin
		Cmd:              exec.Command(pluginDef.ExecutablePath),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           pluginLogger,
	})

	pm.mu.Lock() // Lock again to store the new client
	pm.clients[pluginID] = newClient
	pm.mu.Unlock()

	log.Printf("Launched plugin: %s from %s", pluginID, pluginDef.ExecutablePath)
	return pm.dispensePlugin(newClient, pluginID)
}

func (pm *PluginManager) dispensePlugin(client *plugin.Client, pluginID string) (gwplugin.PluginHookService, error) {
	var rpcClient plugin.ClientProtocol
	var err error

	// Retry loop for client.Client()
	for i := 0; i <= pluginLaunchMaxRetries; i++ {
		rpcClient, err = client.Client()
		if err == nil {
			break
		}
		log.Printf("Error getting RPC client for plugin %s (attempt %d/%d): %v. Retrying in %v...",
			pluginID, i+1, pluginLaunchMaxRetries+1, err, pluginLaunchRetryDelay)
		if i < pluginLaunchMaxRetries {
			time.Sleep(pluginLaunchRetryDelay)
		}
	}
	if err != nil {
		log.Printf("Failed to get RPC client for plugin %s after %d attempts: %v", pluginID, pluginLaunchMaxRetries+1, err)
		client.Kill() // Kill the client process
		pm.mu.Lock()
		delete(pm.clients, pluginID) // Remove from managed clients
		pm.mu.Unlock()
		return nil, fmt.Errorf("error getting RPC client for plugin %s after retries: %w", pluginID, err)
	}

	var raw interface{}
	// Retry loop for rpcClient.Dispense()
	for i := 0; i <= pluginLaunchMaxRetries; i++ {
		raw, err = rpcClient.Dispense(gwplugin.PluginName) // Use PluginName from pkg/plugin
		if err == nil {
			break
		}
		log.Printf("Error dispensing plugin %s (attempt %d/%d): %v. Retrying in %v...",
			pluginID, i+1, pluginLaunchMaxRetries+1, err, pluginLaunchRetryDelay)
		if i < pluginLaunchMaxRetries {
			time.Sleep(pluginLaunchRetryDelay)
		}
	}
	if err != nil {
		log.Printf("Failed to dispense plugin %s after %d attempts: %v", pluginID, pluginLaunchMaxRetries+1, err)
		// If dispensing fails, the client process might still be running but in a bad state.
		client.Kill() // Kill the client process
		pm.mu.Lock()
		delete(pm.clients, pluginID) // Remove from managed clients
		pm.mu.Unlock()
		return nil, fmt.Errorf("error dispensing plugin %s after retries: %w", pluginID, err)
	}

	pluginService, ok := raw.(gwplugin.PluginHookService)
	if !ok {
		log.Printf("Error: dispensed plugin %s is not of type PluginHookService", pluginID)
		return nil, fmt.Errorf("dispensed plugin %s is not of expected type", pluginID)
	}
	return pluginService, nil
}

// convertHTTPRequestToChunk converts an HTTP request to a ProcessingRequestChunk
func (pm *PluginManager) convertHTTPRequestToChunk(
	httpRequest *http.Request,
	routeID string,
	pluginInstanceCfg config.PluginInstanceConfig,
) (*extprocpb.ProcessingRequestChunk, error) {
	// Generate unique request ID
	requestID := fmt.Sprintf("%s-%d", routeID, time.Now().UnixNano())

	// Convert plugin config to protobuf struct
	var pluginConfig *structpb.Struct
	if pluginInstanceCfg.Config != nil {
		var err error
		pluginConfig, err = structpb.NewStruct(pluginInstanceCfg.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to convert plugin config to struct: %w", err)
		}
	}

	// Build request metadata
	requestMetadata := make(map[string]string)
	requestMetadata["route_id"] = routeID
	requestMetadata["plugin_id"] = pluginInstanceCfg.ID
	requestMetadata["remote_addr"] = httpRequest.RemoteAddr
	if httpRequest.Header.Get("User-Agent") != "" {
		requestMetadata["user_agent"] = httpRequest.Header.Get("User-Agent")
	}

	// Convert HTTP headers to plugin format
	headers := make(map[string]*extprocpb.HeaderValue)
	for name, values := range httpRequest.Header {
		headers[name] = &extprocpb.HeaderValue{Values: values}
	}

	chunk := &extprocpb.ProcessingRequestChunk{
		RequestId:       requestID,
		RouteId:         routeID,
		PluginConfig:    pluginConfig,
		RequestMetadata: requestMetadata,
		PhaseData: &extprocpb.ProcessingRequestChunk_RequestHeaders{
			RequestHeaders: &extprocpb.RequestHeaders{
				Headers: &extprocpb.HttpHeaders{
					Headers:     headers,
					EndOfStream: true, // For simplicity, treating as no body for now
				},
				Method:    httpRequest.Method,
				Path:      httpRequest.URL.Path,
				Authority: httpRequest.Host,
				Scheme:    httpRequest.URL.Scheme,
			},
		},
	}

	return chunk, nil
}

// processPluginResponse processes a plugin response and potentially modifies the provider request
func (pm *PluginManager) processPluginResponse(
	response *extprocpb.ProcessingResponseChunk,
	providerRequest *interface{},
) error {
	if response == nil {
		return fmt.Errorf("received nil response from plugin")
	}

	switch action := response.Action.(type) {
	case *extprocpb.ProcessingResponseChunk_CommonResponse:
		if action.CommonResponse.Status == extprocpb.CommonResponse_DENY_REQUEST {
			return fmt.Errorf("plugin denied the request")
		}
		// For CONTINUE_PROCESSING, we proceed normally
		log.Printf("Plugin response: %s", action.CommonResponse.Status.String())

	case *extprocpb.ProcessingResponseChunk_HeaderMutation:
		log.Printf("Plugin requested header mutation with %d headers to set and %d to remove",
			len(action.HeaderMutation.SetHeaders), len(action.HeaderMutation.RemoveHeaders))
		// Header mutations would typically affect the HTTP request/response headers
		// For provider requests, this might not be directly applicable

	case *extprocpb.ProcessingResponseChunk_BodyMutation:
		bodyMutation := action.BodyMutation // bodyMutation is of type *extprocpb.BodyMutation
		if bodyMutation != nil {
			bodyBytes := bodyMutation.GetChunk()
			// endOfStream := bodyMutation.GetEndOfStream() // Available if needed
			log.Printf("Plugin requested body mutation with %d bytes. EndOfStream: %v", len(bodyBytes), bodyMutation.GetEndOfStream())

			// The concept of "ClearBody" isn't explicit in the proto.
			// An empty chunk could signify clearing, or it might be an error/noop.
			// If specific "clear body" logic is needed, the proto might need a dedicated field or message.
			// For now, we only act if bodyBytes has content.
			if len(bodyBytes) > 0 {
				if providerRequest != nil && *providerRequest != nil {
					// Attempt to unmarshal the new body into the existing providerRequest.
					// This assumes the plugin sends JSON compatible with the original type
					// and that *providerRequest is a pointer to the actual data structure.
					err := json.Unmarshal(bodyBytes, *providerRequest)
					if err != nil {
						log.Printf("Error unmarshalling plugin body mutation into provider request: %v. Original request type might not match plugin output, or target is not a pointer to a suitable type.", err)
						// Log and continue with original, effectively ignoring malformed/incompatible mutation.
					} else {
						log.Printf("Successfully applied body mutation from plugin.")
					}
				} else {
					log.Printf("providerRequest or *providerRequest is nil, cannot apply body mutation.")
				}
			} else if bodyMutation.GetChunk() != nil && len(bodyMutation.GetChunk()) == 0 {
				// Explicitly empty chunk received.
				// Depending on semantics, this could mean "clear the body".
				// For now, this is a no-op if len(bodyBytes) == 0 check above handles it.
				// If *providerRequest should be set to an empty/nil state, that logic goes here.
				log.Printf("Plugin sent an empty body chunk. Considering this a no-op for modification.")
			}
		} else {
			log.Printf("Plugin sent BodyMutation action but the BodyMutation field itself was nil.")
		}

	case *extprocpb.ProcessingResponseChunk_ImmediateResponse:
		return fmt.Errorf("plugin requested immediate response with status %d", action.ImmediateResponse.StatusCode)

	default:
		log.Printf("Unknown plugin response action type")
	}

	return nil
}

// Shutdown kills all managed plugin processes.
func (pm *PluginManager) Shutdown() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.healthCheckStop != nil {
		log.Println("Stopping plugin health checker...")
		pm.healthCheckStop()
		pm.healthCheckStop = nil
	}
	if pm.configWatchStop != nil {
		log.Println("Stopping plugin config watcher...")
		pm.configWatchStop()
		pm.configWatchStop = nil
	}

	log.Println("Shutting down all plugins...")
	for id, client := range pm.clients {
		log.Printf("Killing plugin %s...", id)
		client.Kill()
	}
	pm.clients = make(map[string]*plugin.Client) // Clear map
	pm.pluginHealth = make(map[string]bool)      // Clear health status
	log.Println("All plugins shut down.")
}

// ExecutePreRequestHooks executes all configured pre-request plugins for a given route.
// It passes the HTTP request and the typed provider request data.
// Returns the (potentially modified) provider request data or an error.
func (pm *PluginManager) ExecutePreRequestHooks(
	ctx context.Context,
	route *config.RouteConfig,
	httpRequest *http.Request, // Raw HTTP request
	providerRequest interface{}, // Parsed provider-specific request (e.g., provider.ChatCompletionRequest)
) (interface{}, error) {
	if route == nil || len(route.Plugins.Pre) == 0 {
		return providerRequest, nil // No pre-plugins configured for this route
	}

	currentProviderRequest := providerRequest

	// Sort plugins by Order
	sort.SliceStable(route.Plugins.Pre, func(i, j int) bool {
		return route.Plugins.Pre[i].Order < route.Plugins.Pre[j].Order
	})

	for _, pluginInstanceCfg := range route.Plugins.Pre {
		pluginClient, err := pm.GetPluginClient(pluginInstanceCfg.ID)
		if err != nil {
			log.Printf("Error getting client for pre-request plugin %s: %v. Skipping plugin.", pluginInstanceCfg.ID, err)
			// Depending on policy, might continue or return error. For now, continue.
			continue
		}

		log.Printf("Executing pre-request plugin: %s for route %s", pluginInstanceCfg.ID, route.Name)

		// Start the streaming RPC for pre-request processing
		stream, err := pluginClient.PreHandleRequest(ctx)
		if err != nil {
			log.Printf("Error starting pre-request stream for plugin %s: %v. Skipping plugin.", pluginInstanceCfg.ID, err)
			continue
		}

		// Convert HTTP request to plugin request chunk format
		requestChunk, err := pm.convertHTTPRequestToChunk(httpRequest, route.Name, pluginInstanceCfg)
		if err != nil {
			log.Printf("Error converting HTTP request for plugin %s: %v. Skipping plugin.", pluginInstanceCfg.ID, err)
			continue
		}

		// Send the request chunk to the plugin
		if err := stream.Send(requestChunk); err != nil {
			log.Printf("Error sending request chunk to plugin %s: %v. Skipping plugin.", pluginInstanceCfg.ID, err)
			continue
		}

		// Close the send side of the stream
		if err := stream.CloseSend(); err != nil {
			log.Printf("Error closing send stream for plugin %s: %v", pluginInstanceCfg.ID, err)
		}

		// Read the response from the plugin
		for {
			response, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) { // More robust EOF check
					log.Printf("Plugin %s stream ended (EOF).", pluginInstanceCfg.ID)
					break
				}
				log.Printf("Error receiving response from plugin %s for pre-request hook: %v", pluginInstanceCfg.ID, err)
				// Error from plugin's Recv() will propagate and fail the request chain.
				return currentProviderRequest, fmt.Errorf("error receiving response from pre-request plugin %s: %w", pluginInstanceCfg.ID, err)
			}

			// Process the plugin response
			if err := pm.processPluginResponse(response, &currentProviderRequest); err != nil {
				log.Printf("Error processing response from plugin %s: %v", pluginInstanceCfg.ID, err)
				// Error from processing plugin's action (e.g., DENY_REQUEST) will propagate.
				return currentProviderRequest, fmt.Errorf("error processing response from pre-request plugin %s: %w", pluginInstanceCfg.ID, err)
			}
		}
		// Removed extra closing brace here

		log.Printf("Completed pre-request plugin: %s", pluginInstanceCfg.ID)
	}
	return currentProviderRequest, nil
}

// ExecutePostRequestHooks executes all configured post-request plugins for a given route.
// It passes the HTTP request, the typed provider request, and the typed provider response data.
// Returns the (potentially modified) provider response data or an error.
func (pm *PluginManager) ExecutePostRequestHooks(
	ctx context.Context,
	route *config.RouteConfig,
	httpRequest *http.Request, // Raw HTTP request
	providerResponse interface{}, // Parsed provider-specific response (e.g., provider.ChatCompletionResponse)
) (interface{}, error) {
	if route == nil || len(route.Plugins.Post) == 0 {
		return providerResponse, nil // No post-plugins configured for this route
	}

	currentProviderResponse := providerResponse

	// Sort plugins by Order
	sort.SliceStable(route.Plugins.Post, func(i, j int) bool {
		return route.Plugins.Post[i].Order < route.Plugins.Post[j].Order
	})

	for _, pluginInstanceCfg := range route.Plugins.Post {
		pluginClient, err := pm.GetPluginClient(pluginInstanceCfg.ID)
		if err != nil {
			log.Printf("Error getting client for post-request plugin %s: %v. Skipping plugin.", pluginInstanceCfg.ID, err)
			// Depending on policy, might continue or return error. For now, continue.
			continue
		}

		log.Printf("Executing post-request plugin: %s for route %s", pluginInstanceCfg.ID, route.Name)

		// Start the streaming RPC for post-response processing
		stream, err := pluginClient.PostHandleResponse(ctx)
		if err != nil {
			log.Printf("Error starting post-response stream for plugin %s: %v. Skipping plugin.", pluginInstanceCfg.ID, err)
			continue
		}

		// Convert HTTP request to plugin request chunk format (similar to pre-request)
		requestChunk, err := pm.convertHTTPRequestToChunk(httpRequest, route.Name, pluginInstanceCfg)
		if err != nil {
			log.Printf("Error converting HTTP request for plugin %s: %v. Skipping plugin.", pluginInstanceCfg.ID, err)
			continue
		}

		// Send the request chunk to the plugin
		if err := stream.Send(requestChunk); err != nil {
			log.Printf("Error sending request chunk to plugin %s: %v. Skipping plugin.", pluginInstanceCfg.ID, err)
			continue
		}

		// Close the send side of the stream
		if err := stream.CloseSend(); err != nil {
			log.Printf("Error closing send stream for plugin %s: %v", pluginInstanceCfg.ID, err)
		}

		// Read the response from the plugin
		for {
			response, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) { // More robust EOF check
					log.Printf("Plugin %s stream ended (EOF) for post-request hook.", pluginInstanceCfg.ID)
					break
				}
				log.Printf("Error receiving response from plugin %s for post-request hook: %v", pluginInstanceCfg.ID, err)
				// Error from plugin's Recv() will propagate and fail the request chain.
				return currentProviderResponse, fmt.Errorf("error receiving response from post-request plugin %s: %w", pluginInstanceCfg.ID, err)
			}

			// Process the plugin response
			if err := pm.processPluginResponse(response, &currentProviderResponse); err != nil {
				log.Printf("Error processing response from plugin %s: %v", pluginInstanceCfg.ID, err)
				// Error from processing plugin's action (e.g., DENY_REQUEST) will propagate.
				return currentProviderResponse, fmt.Errorf("error processing response from post-request plugin %s: %w", pluginInstanceCfg.ID, err)
			}
		}

		log.Printf("Completed post-request plugin: %s", pluginInstanceCfg.ID)
	}
	return currentProviderResponse, nil
}

// TODO:
// - Implement actual HealthCheck RPC call in `checkAllPluginsHealth` (requires SDK and proto changes).
// - Make health check interval configurable.
// - Further ensure plugin.Client in pm.clients is properly cleaned up if Dispense fails or plugin exits unexpectedly (partially addressed).
// - Expose plugin health status via an admin API endpoint.
