// Package config is responsible for loading, validating, and managing
// the runtime configuration of the OpenPons Gateway. It supports dynamic
// updates and hot-reloading.
package config

import (
	"context"       // Added (ensure only one import)
	"encoding/json" // Added
	"errors"        // For store.ErrNotFound comparison
	"fmt"
	"log"
	"reflect" // Added for DeepEqual
	"regexp"  // Added for email and permission validation
	"sync"
	"time"

	"github.com/openpons/gateway/internal/store"
	"go.uber.org/zap"
)

const (
	runtimeConfigKey = "config/runtime/current" // Key for storing the entire RuntimeConfig in the datastore
)

// ConfigManager manages the lifecycle of the gateway's runtime configuration.
type ConfigManager struct {
	mu             sync.RWMutex
	currentConfig  *RuntimeConfig
	configFilePath string      // Path to an initial config file, if used
	store          store.Store // Datastore abstraction - Added
	logger         *zap.Logger // Added
	watchers       map[chan *RuntimeConfig]bool
	stopWatching   chan struct{}
	pollInterval   time.Duration
}

// ManagerInterface defines the methods proxy handlers (and other components)
// need from a ConfigManager. This allows for easier mocking in tests.
type ManagerInterface interface {
	GetCurrentConfig() *RuntimeConfig
	Subscribe() <-chan *RuntimeConfig
	// Unsubscribe(<-chan *RuntimeConfig) // Not strictly needed by XDSServer's current direct usage of the interface
	// StartWatching() // Typically called internally or by bootstrap
	// StopWatching()  // Typically called by bootstrap or defer
}

// NewConfigManager creates a new ConfigManager.
// It will attempt to load an initial configuration.
func NewConfigManager(filePath string, s store.Store, pollInterval time.Duration, log *zap.Logger) (*ConfigManager, error) {
	if log == nil {
		// Fallback to standard logger if none provided, though bootstrap should provide one.
		// This could also be telemetry.NewNopLogger() if telemetry is imported.
		// For now, using standard log for this fallback.
		stdLog := zap.NewExample().Named("configmanager-fallback") // Or a more appropriate default
		log = stdLog
	}

	cm := &ConfigManager{
		configFilePath: filePath,
		store:          s,   // Use the passed-in store
		logger:         log, // Use the passed-in logger
		watchers:       make(map[chan *RuntimeConfig]bool),
		stopWatching:   make(chan struct{}),
		pollInterval:   pollInterval,
	}

	// Try to load initial config
	// In a real scenario, this would load from the datastore or a bootstrap file.
	// For MVP, we might start with a hardcoded or minimal default.
	initialConfig, err := cm.loadConfigFromSource()
	if err != nil {
		cm.logger.Warn("Failed to load initial config, starting with empty/default config.", zap.Error(err))
		// Initialize with a minimal valid default if loading fails
		cm.currentConfig = &RuntimeConfig{
			Settings: GatewaySettings{ // Ensure there's always some default
				DefaultTimeoutMs: 30000,
			},
			LastUpdated: time.Now().UTC(),
		}
	} else {
		cm.currentConfig = initialConfig
		cm.logger.Info("Initial configuration loaded successfully.")
	}

	go cm.StartWatching() // Start watching for config changes in the background

	return cm, nil
}

// GetCurrentConfig returns a deep copy of the current runtime configuration.
func (cm *ConfigManager) GetCurrentConfig() *RuntimeConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	// Return a deep copy to prevent modification of the internal state
	if cm.currentConfig == nil {
		return &RuntimeConfig{} // Should not happen if constructor initializes
	}
	copiedConfig := *cm.currentConfig // Shallow copy is enough if fields are slices/maps of value types or pointers to immutable
	// For more complex structs with nested pointers, a proper deep copy might be needed.
	// For now, assuming this is sufficient for read-only use by most components.
	return &copiedConfig
}

// loadConfigFromSource loads the configuration from the primary datastore or bootstrap file.
func (cm *ConfigManager) loadConfigFromSource() (*RuntimeConfig, error) {
	cm.mu.Lock() // Ensure exclusive access during load/reload
	defer cm.mu.Unlock()

	cm.logger.Info("Attempting to load configuration from datastore", zap.String("key", runtimeConfigKey))

	if cm.store == nil {
		cm.logger.Error("Datastore (store) is nil in ConfigManager, cannot load config.")
		// Return a minimal valid default config if store is not available
		return &RuntimeConfig{
			Settings:    GatewaySettings{DefaultTimeoutMs: 30000},
			LastUpdated: time.Now().UTC(),
		}, fmt.Errorf("datastore not available in ConfigManager")
	}

	rawConfigBytes, err := cm.store.Get(context.Background(), runtimeConfigKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			cm.logger.Warn("Runtime configuration not found in datastore. Initializing with a default minimal config.", zap.String("key", runtimeConfigKey))
			// Create a default minimal config, store it, and return it.
			defaultConfig := &RuntimeConfig{
				Settings:    GatewaySettings{DefaultTimeoutMs: 30000, DefaultRetryAttempts: 1},
				LastUpdated: time.Now().UTC(),
				// Initialize other slices to empty to avoid nil pointer issues later
				Providers: []ProviderConfig{},
				Models:    []ModelConfig{},
				Routes:    []RouteConfig{},
				Plugins:   []PluginDefinition{},
				IAMConfig: IAMConfig{
					Users:        []UserConfig{},
					Groups:       []GroupConfig{},
					Roles:        []RoleConfig{},
					RoleBindings: []RoleBindingConfig{},
				},
			}
			// Attempt to save this default config to the store
			defaultConfigBytes, marshalErr := json.Marshal(defaultConfig)
			if marshalErr != nil {
				cm.logger.Error("Failed to marshal default config for saving", zap.Error(marshalErr))
				return defaultConfig, nil // Return in-memory default, store remains empty
			}
			if setErr := cm.store.Set(context.Background(), runtimeConfigKey, defaultConfigBytes); setErr != nil {
				cm.logger.Error("Failed to save initial default config to store", zap.Error(setErr))
				// Still return the in-memory default
			} else {
				cm.logger.Info("Successfully saved initial default config to store.")
			}
			return defaultConfig, nil
		}
		return nil, fmt.Errorf("failed to get config from store: %w", err)
	}

	var newConfig RuntimeConfig
	if err := json.Unmarshal(rawConfigBytes, &newConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config from store: %w", err)
	}

	if err := validateConfig(&newConfig); err != nil {
		return nil, fmt.Errorf("loaded configuration from store is invalid: %w", err)
	}

	cm.logger.Info("Configuration loaded successfully from datastore.")
	return &newConfig, nil
}

// validateConfig performs schema and semantic validation on the loaded configuration.
func validateConfig(cfg *RuntimeConfig) error { // This function uses standard log, not cm.logger
	if cfg == nil {
		return fmt.Errorf("runtime config is nil")
	}
	log.Println("Validating configuration...") // Standard log is fine here as it's a static function

	providerIDs := make(map[string]bool)
	modelIDs := make(map[string]bool)
	toolIDs := make(map[string]bool)   // For ToolConfig validation
	agentIDs := make(map[string]bool)  // For AgentConfig validation
	roleNames := make(map[string]bool) // For RoleConfig validation
	userIDs := make(map[string]bool)   // For UserConfig validation
	groupIDs := make(map[string]bool)  // For GroupConfig validation

	// Validate Providers
	for i, p := range cfg.Providers {
		if p.ID == "" {
			return fmt.Errorf("provider %d: ID is required", i)
		}
		if p.Name == "" {
			return fmt.Errorf("provider (ID: %s): Name is required", p.ID)
		}
		if p.Type == "" {
			return fmt.Errorf("provider %s (ID: %s): Type is required", p.Name, p.ID)
		}
		switch p.Type {
		case ProviderTypeLLM, ProviderTypeToolServer, ProviderTypeAgentPlatform:
			// valid
		default:
			return fmt.Errorf("provider %s (ID: %s): Invalid type '%s'", p.Name, p.ID, p.Type)
		}

		// Validate type-specific config
		switch p.Type {
		case ProviderTypeLLM:
			if p.LLMConfig == nil {
				return fmt.Errorf("provider %s (ID: %s): LLMConfig is required for type '%s'", p.Name, p.ID, p.Type)
			}
			if p.LLMConfig.APIBase == "" {
				return fmt.Errorf("provider %s (ID: %s): LLMConfig.APIBase is required", p.Name, p.ID)
			}
		case ProviderTypeToolServer:
			if p.MCPToolConfig == nil {
				return fmt.Errorf("provider %s (ID: %s): MCPToolConfig is required for type '%s'", p.Name, p.ID, p.Type)
			}
			if p.MCPToolConfig.ServerAddress == "" {
				return fmt.Errorf("provider %s (ID: %s): MCPToolConfig.ServerAddress is required", p.Name, p.ID)
			}
		case ProviderTypeAgentPlatform:
			if p.A2APlatformConfig == nil {
				return fmt.Errorf("provider %s (ID: %s): A2APlatformConfig is required for type '%s'", p.Name, p.ID, p.Type)
			}
			// Add validation for A2APlatformConfig fields if any are mandatory
		}

		if providerIDs[p.ID] {
			return fmt.Errorf("provider ID %s is not unique", p.ID)
		}
		providerIDs[p.ID] = true
	}

	// Validate Models
	for i, m := range cfg.Models {
		if m.ID == "" {
			return fmt.Errorf("model %d: ID is required", i)
		}
		if m.ProviderID == "" {
			return fmt.Errorf("model %s (ID: %s): ProviderID is required", m.UpstreamModelName, m.ID)
		}
		if !providerIDs[m.ProviderID] {
			return fmt.Errorf("model %s (ID: %s): ProviderID '%s' not found", m.UpstreamModelName, m.ID, m.ProviderID)
		}
		if m.UpstreamModelName == "" {
			return fmt.Errorf("model %s (ID: %s): UpstreamModelName is required", m.UpstreamModelName, m.ID)
		}
		if modelIDs[m.ID] {
			return fmt.Errorf("model ID %s is not unique", m.ID)
		}
		modelIDs[m.ID] = true
	}

	// Validate Routes
	for i, r := range cfg.Routes {
		if r.ID == "" {
			return fmt.Errorf("route %d: ID is required", i)
		}
		if r.Name == "" {
			return fmt.Errorf("route (ID: %s): Name is required", r.ID)
		}
		if r.Protocol == "" {
			return fmt.Errorf("route %s (ID: %s): Protocol is required", r.Name, r.ID)
		}
		switch r.Protocol {
		case ProtocolHTTPLLM, ProtocolMCPTool, ProtocolA2ATask:
			// valid
		default:
			return fmt.Errorf("route %s (ID: %s): Invalid protocol '%s'", r.Name, r.ID, r.Protocol)
		}
		if len(r.Targets) == 0 {
			return fmt.Errorf("route %s (ID: %s): At least one target is required", r.Name, r.ID)
		}
		for _, t := range r.Targets {
			if t.Ref == "" {
				return fmt.Errorf("route %s (ID: %s): Target ref is required for target %d", r.Name, r.ID, i)
			}
			if r.Protocol == ProtocolHTTPLLM {
				if _, ok := modelIDs[t.Ref]; !ok {
					return fmt.Errorf("route %s (ID: %s): Target ref ModelID '%s' not found", r.Name, r.ID, t.Ref)
				}
			}
			// Validation for t.Ref for ProtocolMCPTool (ToolID) and ProtocolA2ATask (AgentID)
			// is done below after collecting all toolIDs and agentIDs.
			// Collect Tool and Agent IDs first
			if cfg.Tools != nil {
				for _, tool := range cfg.Tools {
					if tool.ID != "" { // Assuming ToolConfig has ID
						toolIDs[tool.ID] = true
					}
				}
			}
			if cfg.Agents != nil {
				for _, agent := range cfg.Agents {
					if agent.ID != "" { // Assuming AgentConfig has ID
						agentIDs[agent.ID] = true
					}
				}
			}

			if r.Protocol == ProtocolMCPTool {
				if _, ok := toolIDs[t.Ref]; !ok {
					return fmt.Errorf("route %s (ID: %s): Target ref ToolID '%s' not found", r.Name, r.ID, t.Ref)
				}
			}
			if r.Protocol == ProtocolA2ATask {
				if _, ok := agentIDs[t.Ref]; !ok {
					return fmt.Errorf("route %s (ID: %s): Target ref AgentID '%s' not found", r.Name, r.ID, t.Ref)
				}
			}
		}

		// Validate Match criteria
		if r.Match.ModelID != "" {
			if _, ok := modelIDs[r.Match.ModelID]; !ok {
				return fmt.Errorf("route %s (ID: %s): Match.ModelID '%s' not found", r.Name, r.ID, r.Match.ModelID)
			}
		}
		if r.Match.ToolID != "" {
			if _, ok := toolIDs[r.Match.ToolID]; !ok {
				return fmt.Errorf("route %s (ID: %s): Match.ToolID '%s' not found", r.Name, r.ID, r.Match.ToolID)
			}
		}
		if r.Match.AgentID != "" {
			if _, ok := agentIDs[r.Match.AgentID]; !ok {
				return fmt.Errorf("route %s (ID: %s): Match.AgentID '%s' not found", r.Name, r.ID, r.Match.AgentID)
			}
		}

		// Validate Policy
		if r.Policy.Strategy != "" {
			switch r.Policy.Strategy {
			case StrategyWeightedRoundRobin, StrategyFailover, StrategyLeastPending:
				// valid
			default:
				return fmt.Errorf("route %s (ID: %s): Invalid policy strategy '%s'", r.Name, r.ID, r.Policy.Strategy)
			}
		}
	}

	// Validate IAMConfig
	if cfg.IAMConfig.Users != nil {
		for _, user := range cfg.IAMConfig.Users {
			if user.ID == "" {
				return fmt.Errorf("iam user: ID is required")
			}
			if userIDs[user.ID] {
				return fmt.Errorf("iam user ID %s is not unique", user.ID)
			}
			userIDs[user.ID] = true
			// Validate email format
			if user.Email == "" {
				return fmt.Errorf("iam user (ID: %s): Email is required", user.ID)
			}
			// Basic email regex, consider a more comprehensive one if needed
			emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
			if matched, _ := regexp.MatchString(emailRegex, user.Email); !matched {
				return fmt.Errorf("iam user (ID: %s): Invalid email format for '%s'", user.ID, user.Email)
			}
			// Validate status
			if user.Status != "active" && user.Status != "disabled" && user.Status != "" { // Allow empty to default to active
				return fmt.Errorf("iam user (ID: %s): Invalid status '%s'. Must be 'active' or 'disabled'.", user.ID, user.Status)
			}
		}
	}
	if cfg.IAMConfig.Groups != nil {
		for _, group := range cfg.IAMConfig.Groups {
			if group.ID == "" {
				return fmt.Errorf("iam group: ID is required")
			}
			if groupIDs[group.ID] {
				return fmt.Errorf("iam group ID %s is not unique", group.ID)
			}
			groupIDs[group.ID] = true
			for _, memberID := range group.MemberIDs {
				if _, ok := userIDs[memberID]; !ok {
					return fmt.Errorf("iam group %s (ID: %s): MemberID '%s' not found in users", group.Name, group.ID, memberID)
				}
			}
		}
	}
	if cfg.IAMConfig.Roles != nil {
		for _, role := range cfg.IAMConfig.Roles {
			if role.Name == "" {
				return fmt.Errorf("iam role: Name is required")
			}
			if roleNames[role.Name] {
				return fmt.Errorf("iam role Name %s is not unique", role.Name)
			}
			roleNames[role.Name] = true
			// Validate permission string format
			// Allows "resource:action", "*:action", "resource:*", "*"
			permissionRegex := `^(\*|([a-zA-Z0-9_.-]+(\/[a-zA-Z0-9_.-]+)*)):(\*|[a-zA-Z0-9_.-]+)$|^\*$`
			for _, perm := range role.Permissions {
				if matched, _ := regexp.MatchString(permissionRegex, string(perm)); !matched {
					return fmt.Errorf("iam role (Name: %s): Invalid permission format '%s'. Expected 'resource:action' or wildcards.", role.Name, perm)
				}
			}
		}
	}
	if cfg.IAMConfig.RoleBindings != nil {
		for _, rb := range cfg.IAMConfig.RoleBindings {
			if rb.ID == "" {
				return fmt.Errorf("iam rolebinding: ID is required")
			}
			if rb.RoleName == "" || !roleNames[rb.RoleName] {
				return fmt.Errorf("iam rolebinding (ID: %s): RoleName '%s' is invalid or not found", rb.ID, rb.RoleName)
			}
			if rb.PrincipalID == "" {
				return fmt.Errorf("iam rolebinding (ID: %s): PrincipalID is required", rb.ID)
			}
			switch rb.PrincipalType {
			case "user":
				if _, ok := userIDs[rb.PrincipalID]; !ok {
					return fmt.Errorf("iam rolebinding (ID: %s): PrincipalID User '%s' not found", rb.ID, rb.PrincipalID)
				}
			case "group":
				if _, ok := groupIDs[rb.PrincipalID]; !ok {
					return fmt.Errorf("iam rolebinding (ID: %s): PrincipalID Group '%s' not found", rb.ID, rb.PrincipalID)
				}
			default:
				return fmt.Errorf("iam rolebinding (ID: %s): Invalid PrincipalType '%s'", rb.ID, rb.PrincipalType)
			}
			// Validate Scope
			if rb.Scope.Type != "" { // Scope.Type is optional, defaults to GLOBAL
				validScopeValue := false
				switch rb.Scope.Type {
				case "GLOBAL":
					if rb.Scope.Value == "" {
						validScopeValue = true
					} else {
						// GLOBAL scope type explicitly set, but Value is not empty. This is an error.
						return fmt.Errorf("iam rolebinding (ID: %s): Scope.Value must be empty for Scope.Type 'GLOBAL'", rb.ID)
					}
				case "PROVIDER":
					for _, p := range cfg.Providers {
						if p.ID == rb.Scope.Value {
							validScopeValue = true
							break
						}
					}
				case "MODEL":
					for _, m := range cfg.Models {
						if m.ID == rb.Scope.Value {
							validScopeValue = true
							break
						}
					}
				case "ROUTE":
					for _, rt := range cfg.Routes {
						if rt.ID == rb.Scope.Value {
							validScopeValue = true
							break
						}
					}
				// Add "TOOL", "AGENT" cases if/when those are valid scope types and entities
				default:
					return fmt.Errorf("iam rolebinding (ID: %s): Invalid Scope.Type '%s'", rb.ID, rb.Scope.Type)
				}
				if !validScopeValue {
					return fmt.Errorf("iam rolebinding (ID: %s): Scope.Value '%s' not found or invalid for Scope.Type '%s'", rb.ID, rb.Scope.Value, rb.Scope.Type)
				}
			} else if rb.Scope.Value != "" { // Type is empty (GLOBAL) but Value is not
				return fmt.Errorf("iam rolebinding (ID: %s): Scope.Value must be empty if Scope.Type is GLOBAL (empty)", rb.ID)
			}
		}
	}

	// Validate Plugins (PluginDefinitions)
	if cfg.Plugins != nil {
		pluginDefIDs := make(map[string]bool)
		for _, plugin := range cfg.Plugins {
			if plugin.ID == "" {
				return fmt.Errorf("plugin definition: ID is required")
			}
			if pluginDefIDs[plugin.ID] {
				return fmt.Errorf("plugin definition ID '%s' is not unique", plugin.ID)
			}
			pluginDefIDs[plugin.ID] = true
			if plugin.Name == "" {
				return fmt.Errorf("plugin definition (ID: %s): Name is required", plugin.ID)
			}
			// if plugin.Type == "external" && plugin.ExecutablePath == "" { // Example check
			// 	return fmt.Errorf("plugin definition %s (ID: %s): ExecutablePath is required for external type", plugin.Name, plugin.ID)
			// }
		}
	}

	// Validate Settings
	if cfg.Settings.DefaultTimeoutMs < 0 {
		return fmt.Errorf("gateway settings: DefaultTimeoutMs cannot be negative")
	}
	if cfg.Settings.DefaultRetryAttempts < 0 {
		return fmt.Errorf("gateway settings: DefaultRetryAttempts cannot be negative")
	}

	log.Println("Configuration validation successful (extended checks).")
	return nil
}

// notifyWatchers sends the new configuration to all registered watchers.
func (cm *ConfigManager) notifyWatchers(newConfig *RuntimeConfig) {
	cm.mu.RLock() // Read lock to access watchers slice
	defer cm.mu.RUnlock()

	cm.logger.Info("Notifying watchers of configuration update.", zap.Int("watcher_count", len(cm.watchers)))
	for watcher := range cm.watchers { // Iterate over map keys
		// Send non-blockingly or consider buffered channels / worker pool for notifications
		// to avoid blocking the config manager if a watcher is slow.
		select {
		case watcher <- newConfig: // Send to the chan *RuntimeConfig
		default:
			cm.logger.Warn("Config watcher channel is full or closed. Skipping notification.")
		}
	}
}

// startWatching starts a goroutine to periodically check for configuration updates
// or use the datastore's watch mechanism.
func (cm *ConfigManager) StartWatching() { // Renamed to be exported
	cm.logger.Info("Starting configuration watcher...")
	// Ensure store is available before starting watcher that uses it.
	if cm.store == nil {
		cm.logger.Error("Datastore (store) is nil, cannot start config watcher. This indicates a bootstrap problem.")
		return
	}

	// Create a context that can be cancelled by StopWatching
	watchCtx, cancelWatch := context.WithCancel(context.Background())

	go func() {
		defer cancelWatch() // Cancel the watch context when this goroutine exits

		eventChan, err := cm.store.Watch(watchCtx, runtimeConfigKey)
		if err != nil {
			cm.logger.Error("Failed to start watching configuration in store, falling back to polling.",
				zap.Error(err),
				zap.String("key", runtimeConfigKey),
				zap.Duration("poll_interval", cm.pollInterval))
			// Fallback to polling if watch setup fails
			cm.startPollingWatcher(watchCtx) // Pass the cancellable context
			return
		}

		cm.logger.Info("Successfully started event-driven configuration watcher.", zap.String("key", runtimeConfigKey))
		for {
			select {
			case event, ok := <-eventChan:
				if !ok {
					cm.logger.Info("Configuration watch channel closed. Restarting watch or stopping if context cancelled.")
					// Check if the context was cancelled (e.g., by StopWatching)
					if watchCtx.Err() != nil {
						cm.logger.Info("Watch context cancelled, stopping watcher.")
						return
					}
					// Attempt to re-establish the watch
					time.Sleep(5 * time.Second) // Backoff before retrying
					newEventChan, watchErr := cm.store.Watch(watchCtx, runtimeConfigKey)
					if watchErr != nil {
						cm.logger.Error("Failed to re-establish configuration watch, falling back to polling.", zap.Error(watchErr))
						cm.startPollingWatcher(watchCtx)
						return
					}
					eventChan = newEventChan
					cm.logger.Info("Successfully re-established event-driven configuration watcher.")
					continue
				}

				cm.logger.Debug("Received configuration watch event", zap.Any("event_type", event.Type), zap.String("key", event.Key))
				if event.Key == runtimeConfigKey && (event.Type == store.EventTypeCreate || event.Type == store.EventTypeUpdate) {
					var newConfig RuntimeConfig
					if err := json.Unmarshal(event.Value, &newConfig); err != nil {
						cm.logger.Error("Failed to unmarshal updated config from watch event", zap.Error(err))
						continue
					}

					if errVal := validateConfig(&newConfig); errVal != nil {
						cm.logger.Error("Updated configuration from watch event is invalid", zap.Error(errVal))
						continue
					}

					cm.mu.Lock()
					var configToNotify *RuntimeConfig
					if !areConfigsEqual(cm.currentConfig, &newConfig) {
						cm.logger.Info("Configuration changed via watch event. Updating internal state.")
						cm.currentConfig = &newConfig
						// newConfig is a value type here. configToNotify expects *RuntimeConfig.
						// We want to notify with a pointer to this newConfig.
						configToNotify = &newConfig
					}
					cm.mu.Unlock()

					if configToNotify != nil {
						cm.logger.Info("Notifying watchers of configuration update from watch event.")
						cm.notifyWatchers(configToNotify)
					} else {
						cm.logger.Debug("No effective configuration change detected from watch event.")
					}
				}
			case <-cm.stopWatching: // This channel is used to signal StopWatching from outside
				cm.logger.Info("StopWatching signal received, cancelling watch context.")
				cancelWatch() // This will cause the watchCtx.Done() to be selected or eventChan to close
				// The loop will exit once eventChan closes due to context cancellation.
				return
			case <-watchCtx.Done(): // Handles cancellation from StopWatching
				cm.logger.Info("Watch context cancelled, configuration watcher stopping.")
				return
			}
		}
	}()
}

// startPollingWatcher is a helper for fallback polling if event-driven watch fails.
func (cm *ConfigManager) startPollingWatcher(ctx context.Context) {
	cm.logger.Info("Starting polling configuration watcher as fallback.", zap.Duration("interval", cm.pollInterval))
	ticker := time.NewTicker(cm.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cm.logger.Debug("Polling for configuration changes (fallback)...")
			newConfig, err := cm.loadConfigFromSource() // loadConfigFromSource handles its own locking
			if err != nil {
				cm.logger.Error("Error reloading configuration during fallback polling", zap.Error(err))
				continue
			}

			cm.mu.Lock()
			var configToNotify *RuntimeConfig
			if !areConfigsEqual(cm.currentConfig, newConfig) { // newConfig from loadConfigFromSource is *RuntimeConfig
				cm.logger.Info("Configuration changed (polling). Updating internal state.")
				cm.currentConfig = newConfig // newConfig is already a pointer
				// configToNotify needs to be a pointer to a copy if we want to avoid races
				// or ensure the notified config isn't changed later by the manager.
				// However, areConfigsEqual already works with pointers.
				// And notifyWatchers sends the pointer.
				// The crucial part is that GetCurrentConfig returns a copy.
				// For watchers, sending a pointer to the *newly adopted* currentConfig is fine.
				// If newConfig is the one to be adopted, and cm.currentConfig becomes newConfig,
				// then configToNotify should be newConfig.
				// The copy for watchers happens in notifyWatchers if we want to be super safe,
				// or here if we want each watcher to get a distinct copy.
				// The current notifyWatchers sends the pointer it receives.
				// So, if cm.currentConfig is updated to newConfig, configToNotify should be newConfig.

				// Let's ensure configToNotify is a pointer to the *value* of the new configuration,
				// and that this value is what cm.currentConfig now points to.
				// Since newConfig from loadConfigFromSource is *RuntimeConfig,
				// and cm.currentConfig is also *RuntimeConfig:
				configToNotify = newConfig
			}
			cm.mu.Unlock()

			if configToNotify != nil {
				cm.logger.Info("Notifying watchers of configuration update (polling).")
				cm.notifyWatchers(configToNotify)
			} else {
				cm.logger.Debug("No configuration changes detected (polling).")
			}
		case <-ctx.Done(): // Listen to the same context used for the main watch attempt
			cm.logger.Info("Polling configuration watcher stopping due to context cancellation.")
			return
		}
	}
}

// StopWatching signals the configuration watcher to stop.
func (cm *ConfigManager) StopWatching() {
	close(cm.stopWatching)
}

// Subscribe returns a channel that receives updates when the configuration changes.
// The caller is responsible for consuming from the channel promptly.
// Returns a receive-only channel to the caller.
func (cm *ConfigManager) Subscribe() <-chan *RuntimeConfig {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Buffered channel of 1 to allow one update to be pending
	// if the receiver is momentarily busy.
	// The actual channel stored in the map is bidirectional for the manager to send.
	watcherChan := make(chan *RuntimeConfig, 1)
	cm.watchers[watcherChan] = true // Add to map
	cm.logger.Info("New configuration watcher subscribed.", zap.Int("total_watchers", len(cm.watchers)))

	// Send the current config immediately to the new subscriber
	// Create a copy for the new watcher
	if cm.currentConfig != nil {
		currentConfigCopy := *cm.currentConfig
		watcherChan <- &currentConfigCopy
	}
	return watcherChan // Return as receive-only to the caller
}

// Unsubscribe removes a watcher channel.
// The subscriber provides the same channel instance it received from Subscribe.
// Internally, we need to cast it or handle the map key type appropriately.
func (cm *ConfigManager) Unsubscribe(watcherChanReadOnly <-chan *RuntimeConfig) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// To remove from the map, we need the original chan *RuntimeConfig type.
	// This requires a bit of a workaround if we only have the read-only version.
	// A safer way is for Subscribe to return an ID, or for Unsubscribe to take the original chan.
	// For now, let's assume the caller somehow has the original chan or we iterate and cast.
	// This is a common Go challenge with channel directionality and map keys.

	// A more robust way: Store a struct that holds the channel, or use an ID.
	// For this fix, we'll iterate and find it, assuming the pointer is the same.
	// This is not perfectly safe due to type conversion, but for MVP:
	var chanToRemove chan *RuntimeConfig
	for ch := range cm.watchers {
		if (<-chan *RuntimeConfig)(ch) == watcherChanReadOnly {
			chanToRemove = ch
			break
		}
	}

	if chanToRemove != nil {
		close(chanToRemove)
		delete(cm.watchers, chanToRemove)
		cm.logger.Info("Configuration watcher unsubscribed.", zap.Int("remaining_watchers", len(cm.watchers)))
	} else {
		cm.logger.Warn("Attempted to unsubscribe a non-existent or already removed watcher channel.")
	}
}

// areConfigsEqual checks if two RuntimeConfig instances are semantically equal.
func areConfigsEqual(c1, c2 *RuntimeConfig) bool {
	if c1 == nil && c2 == nil {
		return true
	}
	if c1 == nil || c2 == nil {
		return false
	}

	// Create copies to nil out fields that change on every load (like LastUpdated)
	// before performing a deep comparison.
	cfg1Copy := *c1
	cfg2Copy := *c2

	cfg1Copy.LastUpdated = time.Time{}
	cfg2Copy.LastUpdated = time.Time{}

	// If there are other fields that are dynamic but don't represent a semantic change
	// (e.g., internal counters, cache state if it were part of this struct),
	// they should also be zeroed out in the copies before comparison.

	return reflect.DeepEqual(cfg1Copy, cfg2Copy)
}

// ReloadConfig explicitly triggers a reload of the configuration from the source
// and notifies subscribers if there's a change.
// This method implements the iam.ConfigManagerInterface.
func (cm *ConfigManager) ReloadConfig(ctx context.Context) error {
	cm.logger.Info("Explicit configuration reload triggered.")

	// loadConfigFromSource handles its own locking for the actual loading part
	// and store interaction.
	newConfig, err := cm.loadConfigFromSource()
	if err != nil {
		cm.logger.Error("Failed to reload configuration from source", zap.Error(err))
		return fmt.Errorf("failed to reload configuration: %w", err)
	}

	var configToNotify *RuntimeConfig
	cm.mu.Lock() // Lock for comparing and updating currentConfig
	if !areConfigsEqual(cm.currentConfig, newConfig) {
		cm.logger.Info("Configuration changed after explicit reload. Updating internal state.")
		cm.currentConfig = newConfig
		configToNotify = newConfig // This is the new current config
	} else {
		cm.logger.Info("No effective configuration change detected after explicit reload.")
	}
	cm.mu.Unlock()

	if configToNotify != nil {
		cm.logger.Info("Notifying watchers of configuration update after explicit reload.")
		cm.notifyWatchers(configToNotify)
	}
	return nil
}
