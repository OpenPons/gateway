// Package routing is responsible for translating high-level route objects
// into concrete upstream targets. It handles logic for load balancing,
// failover, canary weighting, and applying route-specific policies.
package routing

import (
	"context"
	"fmt"
	"log"
	"math" // For math.MaxInt32
	"math/rand"
	"net/http" // For request context, e.g. headers for matching
	"strings"
	"sync"
	"sync/atomic" // For pending request counters
	"time"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/provider"
)

// Router resolves an incoming request to a target provider adapter based on routing rules.
type Router struct {
	configManager    *config.ConfigManager
	providerRegistry *provider.Registry // Registry to get live adapter instances

	// For weighted round-robin, we might need to store some state per route,
	// or re-calculate on each request if weights don't change often.
	// For simplicity, MVP might do random weighted selection.
	rngLock sync.Mutex
	rng     *rand.Rand

	// For least_pending strategy
	pendingRequests     map[string]*int32 // Key: target.Ref (ModelID, ToolID, AgentID)
	pendingRequestsLock sync.RWMutex      // To protect the map itself during init or if targets are dynamic
}

// RouterInterface defines the methods proxy handlers (and other components)
// need from a Router. This allows for easier mocking in tests.
type RouterInterface interface {
	ResolveRoute(ctx context.Context, reqCtx IncomingRequestContext) (*ResolvedTarget, error)
	// Add other methods like IncrementPendingRequests if they were part of a public API used by handlers
}

// NewRouter creates a new Router.
func NewRouter(cm *config.ConfigManager, pr *provider.Registry) *Router {
	return &Router{
		configManager:    cm,
		providerRegistry: pr,
		rng:              rand.New(rand.NewSource(time.Now().UnixNano())),
		pendingRequests:  make(map[string]*int32),
		// pendingRequestsLock is zero-value ready
	}
}

// IncrementPendingRequests increments the pending request counter for a target.
func (r *Router) IncrementPendingRequests(targetRef string) {
	r.pendingRequestsLock.RLock()
	counter, exists := r.pendingRequests[targetRef]
	r.pendingRequestsLock.RUnlock()

	if !exists {
		r.pendingRequestsLock.Lock()
		// Double check after acquiring write lock
		counter, exists = r.pendingRequests[targetRef]
		if !exists {
			var newCounter int32
			r.pendingRequests[targetRef] = &newCounter
			counter = &newCounter
		}
		r.pendingRequestsLock.Unlock()
	}
	atomic.AddInt32(counter, 1)
}

// DecrementPendingRequests decrements the pending request counter for a target.
func (r *Router) DecrementPendingRequests(targetRef string) {
	r.pendingRequestsLock.RLock()
	counter, exists := r.pendingRequests[targetRef]
	r.pendingRequestsLock.RUnlock()

	if exists {
		atomic.AddInt32(counter, -1)
	} else {
		// This case should ideally not happen if Increment was called first.
		// Log a warning or handle as appropriate.
		log.Printf("Router: DecrementPendingRequests called for unknown targetRef %s", targetRef)
	}
}

// GetPendingRequests returns the current pending request count for a target.
func (r *Router) GetPendingRequests(targetRef string) int32 {
	r.pendingRequestsLock.RLock()
	counterPtr, exists := r.pendingRequests[targetRef]
	r.pendingRequestsLock.RUnlock()

	if !exists {
		return 0 // If no counter exists, assume 0 pending requests
	}
	return atomic.LoadInt32(counterPtr)
}

// IncomingRequestContext holds information about the request relevant for routing.
type IncomingRequestContext struct {
	Path     string
	Method   string
	Headers  http.Header
	ModelID  string              // If specified in path or request body
	ToolID   string              // If specified
	AgentID  string              // If specified
	TaskName string              // For A2A
	Protocol config.ProtocolType // Deduced from path or endpoint
	// UserPrincipal iam.Principal // Authenticated user/service account
}

// ResolvedTarget represents the chosen upstream target and applied policies.
type ResolvedTarget struct {
	Adapter provider.ProviderAdapter
	Route   *config.RouteConfig // The route that matched
	Target  *config.RouteTarget // The specific target within the route
	// EffectivePolicy config.RoutePolicy // Merged global/route/target policies
}

// ResolveRoute finds the best matching route and selects a target provider adapter.
func (r *Router) ResolveRoute(ctx context.Context, reqCtx IncomingRequestContext) (*ResolvedTarget, error) {
	currentCfg := r.configManager.GetCurrentConfig()
	if currentCfg == nil {
		return nil, fmt.Errorf("router: configuration not available")
	}

	var bestMatch *config.RouteConfig
	var matchingRoutes []*config.RouteConfig

	for i := range currentCfg.Routes {
		route := &currentCfg.Routes[i] // Use pointer to the slice element
		if routeMatches(reqCtx, &route.Match) {
			matchingRoutes = append(matchingRoutes, route)
		}
	}

	if len(matchingRoutes) == 0 {
		return nil, fmt.Errorf("router: no matching route found for request")
	}

	// Select the best match based on priority (lower value means higher priority)
	bestMatch = matchingRoutes[0]
	for _, route := range matchingRoutes[1:] {
		// Default priority to a high number if not set, to make routes with explicit priority take precedence.
		currentBestPriority := bestMatch.Priority
		if currentBestPriority == 0 { // Assuming 0 can be a valid priority or means "default/lowest"
			// For this logic, let's treat 0 as a very low priority if other routes have explicit non-zero priorities.
			// A common convention is that lower number = higher priority.
			// If a route has priority 0 (or not set), it's less specific than one with e.g. 100.
			// Let's assume 0 means "not set" and give it a high numerical value for sorting.
			// Or, ensure Priority always has a sensible default in config loading (e.g. MaxInt / 2).
			// For now, if Priority is 0, consider it lower than any positive priority.
			// This logic needs to be robust based on how Priority is defined and defaulted.
			// Let's assume lower integer = higher priority. If 0 is default, it's lowest.
		}

		routePriority := route.Priority
		// This simple comparison assumes lower number is higher priority.
		// And that unset (0) is lower priority than set (non-zero).
		// This might need adjustment based on how '0' priority is treated.
		// If 0 is a valid, highest priority, this logic is wrong.
		// Assuming standard: lower number = higher prio. 0 could be default/lowest or highest.
		// Let's assume for now: if a priority is set (non-zero), it's considered.
		// If both are 0, first one found wins. If one is 0 and other non-zero, non-zero wins (if it's lower).
		// This needs a clear definition of default priority. Let's assume 0 is a valid priority.
		if routePriority < currentBestPriority {
			bestMatch = route
		}
		// If priorities are equal, the first one encountered (based on original list order) is kept.
	}
	log.Printf("Router: Request best matched route '%s' (ID: %s, Priority: %d)", bestMatch.Name, bestMatch.ID, bestMatch.Priority)

	matchedRoute := bestMatch // Use the bestMatch from now on

	if len(matchedRoute.Targets) == 0 {
		return nil, fmt.Errorf("router: matched route '%s' has no targets configured", matchedRoute.Name)
	}

	// Implement target selection based on route policy
	strategy := matchedRoute.Policy.Strategy
	if strategy == "" {
		strategy = config.StrategyWeightedRoundRobin // Default strategy
	}

	var selectedTargetConfig *config.RouteTarget
	var err error

	switch strategy {
	case config.StrategyWeightedRoundRobin:
		selectedTargetConfig, err = selectTargetWeightedRandom(matchedRoute.Targets, r.rng, &r.rngLock)
	case config.StrategyFailover:
		selectedTargetConfig, err = selectTargetFailover(matchedRoute.Targets, r.providerRegistry, currentCfg, matchedRoute.Protocol) // Pass matchedRoute.Protocol
	case config.StrategyLeastPending:
		selectedTargetConfig, err = r.selectTargetLeastPending(matchedRoute.Targets, r.providerRegistry, currentCfg, matchedRoute.Protocol)
		if err != nil {
			log.Printf("Router: Strategy '%s' failed for route '%s': %v. Defaulting to weighted_round_robin.", strategy, matchedRoute.Name, err)
			selectedTargetConfig, err = selectTargetWeightedRandom(matchedRoute.Targets, r.rng, &r.rngLock)
		}
	default:
		log.Printf("Router: Unknown strategy '%s', defaulting to weighted_round_robin for route '%s'", strategy, matchedRoute.Name)
		selectedTargetConfig, err = selectTargetWeightedRandom(matchedRoute.Targets, r.rng, &r.rngLock)
	}

	if err != nil {
		return nil, fmt.Errorf("router: failed to select target for route '%s' using strategy '%s': %w", matchedRoute.Name, strategy, err)
	}
	if selectedTargetConfig == nil { // Should be caught by specific selector errors
		return nil, fmt.Errorf("router: no target selected for route '%s' with strategy '%s'", matchedRoute.Name, strategy)
	}

	// Get the actual provider.ProviderAdapter instance for selectedTargetConfig.Ref
	// This requires a provider registry or a way to instantiate/fetch adapters.
	// adapter := r.providerRegistry.GetAdapter(selectedTargetConfig.Ref)
	// if adapter == nil {
	//  return nil, fmt.Errorf("router: no provider adapter found for target ref '%s'", selectedTargetConfig.Ref)
	// }

	// Determine the ProviderID for the selected target.
	// selectedTargetConfig.Ref is the ModelID, ToolID, or AgentID.
	var targetProviderID string
	var targetResourceName string // For logging/error messages

	switch reqCtx.Protocol {
	case config.ProtocolHTTPLLM:
		for _, m := range currentCfg.Models {
			if m.ID == selectedTargetConfig.Ref {
				targetProviderID = m.ProviderID
				targetResourceName = m.UpstreamModelName
				break
			}
		}
	case config.ProtocolMCPTool:
		for _, t := range currentCfg.Tools { // Assuming RuntimeConfig has Tools []ToolConfig
			if t.ID == selectedTargetConfig.Ref {
				targetProviderID = t.ProviderID
				targetResourceName = t.UpstreamToolName // Use UpstreamToolName
				break
			}
		}
	case config.ProtocolA2ATask:
		for _, ag := range currentCfg.Agents { // Assuming RuntimeConfig has Agents []AgentConfig
			if ag.ID == selectedTargetConfig.Ref {
				targetProviderID = ag.ProviderID
				targetResourceName = ag.UpstreamAgentID // Use UpstreamAgentID
				break
			}
		}
	default:
		return nil, fmt.Errorf("router: unsupported protocol '%s' for target lookup", reqCtx.Protocol)
	}

	if targetProviderID == "" {
		return nil, fmt.Errorf("router: could not determine provider ID for target ref '%s' (name: %s, protocol: %s)", selectedTargetConfig.Ref, targetResourceName, reqCtx.Protocol)
	}

	// Get the actual provider.ProviderAdapter instance from the registry.
	adapter, err := r.providerRegistry.GetAdapter(targetProviderID)
	if err != nil {
		return nil, fmt.Errorf("router: failed to get provider adapter for provider ID '%s' (target ref '%s'): %w", targetProviderID, selectedTargetConfig.Ref, err)
	}
	if adapter == nil { // Should be caught by GetAdapter error, but defensive check
		return nil, fmt.Errorf("router: no provider adapter found for provider ID '%s' (target ref '%s')", targetProviderID, selectedTargetConfig.Ref)
	}

	resolved := &ResolvedTarget{
		Adapter: adapter,
		Route:   matchedRoute,
		Target:  selectedTargetConfig,
		// EffectivePolicy: calculateEffectivePolicy(currentCfg.Settings, matchedRoute.Policy, selectedTargetConfig.Policy),
	}

	// Retry and timeout logic are currently handled at the proxy handler level (e.g., chat_handler.go)
	// based on the resolved RoutePolicy. Centralizing this further into a generic router wrapper
	// was considered but deemed overly complex for varying adapter method signatures and streaming.
	// A shared utility function for handlers to use is a more viable approach if duplication becomes an issue.

	log.Printf("Router: Resolved request to target '%s' via route '%s'", selectedTargetConfig.Ref, matchedRoute.Name)
	return resolved, nil
}

func routeMatches(reqCtx IncomingRequestContext, match *config.RouteMatch) bool {
	// PathPrefix match
	if match.PathPrefix != "" && !strings.HasPrefix(reqCtx.Path, match.PathPrefix) {
		return false
	}
	// ModelID match (only if protocol indicates LLM)
	if reqCtx.Protocol == config.ProtocolHTTPLLM && match.ModelID != "" && reqCtx.ModelID != match.ModelID {
		return false
	}
	// ToolID match
	if reqCtx.Protocol == config.ProtocolMCPTool && match.ToolID != "" && reqCtx.ToolID != match.ToolID {
		return false
	}
	// AgentID match
	if reqCtx.Protocol == config.ProtocolA2ATask && match.AgentID != "" && reqCtx.AgentID != match.AgentID {
		return false
	}
	// TaskName match (for A2A)
	if reqCtx.Protocol == config.ProtocolA2ATask && match.TaskName != "" && reqCtx.TaskName != match.TaskName {
		return false
	}
	// Header match
	for k, v := range match.Headers {
		if reqCtx.Headers.Get(k) != v {
			return false
		}
	}
	return true
}

func selectTargetWeightedRandom(targets []config.RouteTarget, rng *rand.Rand, rngLock *sync.Mutex) (*config.RouteTarget, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets in route for weighted random selection")
	}
	totalWeight := 0
	for _, t := range targets {
		if t.Weight <= 0 { // Treat non-positive weights as 0 for this strategy, effectively excluding them unless all are 0
			t.Weight = 0
		}
		totalWeight += t.Weight
	}

	if totalWeight == 0 {
		// If all targets have 0 weight, distribute load equally by picking one at random.
		// Or, could pick the first one as a deterministic fallback.
		log.Println("Router: All target weights are 0 for weighted_round_robin, picking a target at random from available.")
		rngLock.Lock()
		idx := rng.Intn(len(targets))
		rngLock.Unlock()
		return &targets[idx], nil
	}

	rngLock.Lock()
	rValue := rng.Intn(totalWeight)
	rngLock.Unlock()

	cumulativeWeight := 0
	for i, t := range targets {
		if t.Weight > 0 { // Only consider targets with positive weight
			cumulativeWeight += t.Weight
			if rValue < cumulativeWeight {
				return &targets[i], nil
			}
		}
	}
	// Fallback, should ideally not be reached if totalWeight > 0 and weights are positive.
	// This could happen if all positive-weighted targets were somehow skipped.
	// Pick the last target with positive weight, or first if none.
	for i := len(targets) - 1; i >= 0; i-- {
		if targets[i].Weight > 0 {
			return &targets[i], nil
		}
	}
	return &targets[0], nil // Absolute fallback: pick the first target
}

func selectTargetFailover(targets []config.RouteTarget, reg provider.RegistryInterface, currentCfg *config.RuntimeConfig, protocol config.ProtocolType) (*config.RouteTarget, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets in route for failover selection")
	}
	// Targets are assumed to be in failover order (primary, secondary, etc.)
	for i, target := range targets {
		// Determine ProviderID for this target
		var targetProviderID string

		switch protocol {
		case config.ProtocolHTTPLLM:
			for _, m := range currentCfg.Models {
				if m.ID == target.Ref {
					targetProviderID = m.ProviderID
					break
				}
			}
		case config.ProtocolMCPTool:
			for _, t := range currentCfg.Tools {
				if t.ID == target.Ref {
					targetProviderID = t.ProviderID
					break
				}
			}
		case config.ProtocolA2ATask:
			for _, ag := range currentCfg.Agents {
				if ag.ID == target.Ref {
					targetProviderID = ag.ProviderID
					break
				}
			}
		default:
			log.Printf("Router (Failover): Unsupported protocol '%s' for target ref '%s', skipping.", protocol, target.Ref)
			continue
		}

		if targetProviderID == "" {
			log.Printf("Router (Failover): Could not determine provider ID for target ref '%s' (protocol %s), skipping.", target.Ref, protocol)
			continue
		}

		adapter, err := reg.GetAdapter(targetProviderID)
		if err != nil {
			log.Printf("Router (Failover): Adapter for provider ID '%s' (target '%s') not found or error: %v. Trying next target.", targetProviderID, target.Ref, err)
			continue
		}

		// Perform a health check on the adapter/target
		// The HealthCheck method on the adapter should be lightweight.
		healthCheckCtx, healthCheckCancel := context.WithTimeout(context.Background(), 2*time.Second) // Short timeout for health check
		errHealthCheck := adapter.HealthCheck(healthCheckCtx)
		healthCheckCancel() // Ensure context is cancelled immediately after the check

		if errHealthCheck == nil {
			log.Printf("Router (Failover): Selected healthy target '%s' (index %d).", target.Ref, i)
			return &targets[i], nil // Found a healthy target
		}
		log.Printf("Router (Failover): Target '%s' (provider %s) failed health check: %v. Trying next target.", target.Ref, targetProviderID, errHealthCheck)
	}
	return nil, fmt.Errorf("all targets in failover list are unhealthy or unavailable")
}

func (r *Router) selectTargetLeastPending(targets []config.RouteTarget, reg provider.RegistryInterface, currentCfg *config.RuntimeConfig, protocol config.ProtocolType) (*config.RouteTarget, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets in route for least pending selection")
	}

	var bestTarget *config.RouteTarget
	minPending := int32(math.MaxInt32)
	foundHealthyTarget := false

	// In case all healthy targets have MaxInt32 pending requests, or to break ties,
	// we can collect all targets with minPending and pick one randomly.
	var candidates []*config.RouteTarget

	for i := range targets {
		target := &targets[i] // Use pointer to iterate

		// Determine ProviderID for health check (similar to selectTargetFailover)
		var targetProviderID string
		switch protocol {
		case config.ProtocolHTTPLLM:
			for _, m := range currentCfg.Models {
				if m.ID == target.Ref {
					targetProviderID = m.ProviderID
					break
				}
			}
		case config.ProtocolMCPTool:
			for _, t := range currentCfg.Tools {
				if t.ID == target.Ref {
					targetProviderID = t.ProviderID
					break
				}
			}
		case config.ProtocolA2ATask:
			for _, ag := range currentCfg.Agents {
				if ag.ID == target.Ref {
					targetProviderID = ag.ProviderID
					break
				}
			}
		default:
			log.Printf("Router (LeastPending): Unsupported protocol '%s' for target ref '%s', skipping.", protocol, target.Ref)
			continue
		}

		if targetProviderID == "" {
			log.Printf("Router (LeastPending): Could not determine provider ID for target ref '%s' (protocol %s), skipping.", target.Ref, protocol)
			continue
		}

		adapter, err := reg.GetAdapter(targetProviderID)
		if err != nil {
			log.Printf("Router (LeastPending): Adapter for provider ID '%s' (target '%s') not found or error: %v. Skipping.", targetProviderID, target.Ref, err)
			continue
		}

		healthCheckCtx, healthCheckCancel := context.WithTimeout(context.Background(), 2*time.Second)
		errHealthCheck := adapter.HealthCheck(healthCheckCtx)
		healthCheckCancel()

		if errHealthCheck != nil {
			log.Printf("Router (LeastPending): Target '%s' (provider %s) failed health check: %v. Skipping.", target.Ref, targetProviderID, errHealthCheck)
			continue
		}

		// Target is healthy, get its pending requests
		foundHealthyTarget = true
		currentPending := r.GetPendingRequests(target.Ref) // target.Ref is ModelID, ToolID, or AgentID

		if currentPending < minPending {
			minPending = currentPending
			candidates = []*config.RouteTarget{target} // Reset candidates
		} else if currentPending == minPending {
			candidates = append(candidates, target)
		}
	}

	if !foundHealthyTarget {
		return nil, fmt.Errorf("no healthy targets available for least pending selection")
	}

	if len(candidates) == 0 {
		// This should not happen if foundHealthyTarget is true. Defensive.
		return nil, fmt.Errorf("no candidates found for least pending selection despite healthy targets")
	}

	// If multiple targets have the same minPending, pick one randomly from candidates.
	if len(candidates) > 1 {
		r.rngLock.Lock()
		idx := r.rng.Intn(len(candidates))
		r.rngLock.Unlock()
		bestTarget = candidates[idx]
	} else {
		bestTarget = candidates[0]
	}

	log.Printf("Router (LeastPending): Selected target '%s' with %d pending requests.", bestTarget.Ref, minPending)
	return bestTarget, nil
}
