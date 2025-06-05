package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"regexp" // Added for permission format validation

	"github.com/openpons/gateway/internal/config"

	"github.com/openpons/gateway/internal/iam"
	"github.com/openpons/gateway/internal/secrets"
	"github.com/openpons/gateway/internal/store"
	prometheusv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	pmodel "github.com/prometheus/common/model"
)

var validPermissionFormat = regexp.MustCompile(`^[a-zA-Z0-9_*-]+:[a-zA-Z0-9_*-]+$`)

// isValidPermissionFormat checks if a permission string matches "resource:action" format.
// Allows alphanumeric, underscore, hyphen, and asterisk.
func isValidPermissionFormatHelper(perm string) bool {
	return validPermissionFormat.MatchString(perm)
}

// PrometheusClient defines the interface for a Prometheus API client.
type PrometheusClient interface {
	Query(ctx context.Context, query string, ts time.Time, opts ...prometheusv1.Option) (pmodel.Value, prometheusv1.Warnings, error)
	QueryRange(ctx context.Context, query string, r prometheusv1.Range, opts ...prometheusv1.Option) (pmodel.Value, prometheusv1.Warnings, error)
}

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	store         store.Store
	configMgr     *config.ConfigManager
	secretManager secrets.SecretManagementService
	iamService    *iam.Service
	metricsClient PrometheusClient // Client for querying metrics
}

// NewHandler creates a new Handler.
func NewHandler(s store.Store, cm *config.ConfigManager, sm secrets.SecretManagementService, iamSvc *iam.Service, mc PrometheusClient) *Handler {
	return &Handler{
		store:         s,
		configMgr:     cm,
		secretManager: sm,
		iamService:    iamSvc,
		metricsClient: mc,
	}
}

func (h *Handler) placeholderHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"message": "Endpoint not yet implemented."})
}

// --- Utility Functions ---

// getPaginationParams extracts limit and offset from query parameters
func getPaginationParams(params url.Values) (limit, offset int) {
	limit = 10 // default
	offset = 0 // default

	if l := params.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	if o := params.Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	return limit, offset
}

// paginate applies pagination to a slice
func paginate[T any](items []T, offset, limit int) []T {
	if offset >= len(items) {
		return []T{}
	}

	end := offset + limit
	if end > len(items) {
		end = len(items)
	}

	return items[offset:end]
}

// --- Usage Statistics Handlers ---

// UsageStats represents aggregated usage statistics
type UsageStats struct {
	Timestamp             time.Time        `json:"timestamp"`
	TotalRequests         int64            `json:"total_requests"`
	TotalTokensProcessed  int64            `json:"total_tokens_processed"`
	TotalCostUSD          float64          `json:"total_cost_usd"`
	RequestsByModel       map[string]int64 `json:"requests_by_model"`
	RequestsByProvider    map[string]int64 `json:"requests_by_provider"`
	RequestsByRoute       map[string]int64 `json:"requests_by_route"`
	ErrorsByType          map[string]int64 `json:"errors_by_type"`
	AverageResponseTimeMs float64          `json:"average_response_time_ms"`
	ActiveConnections     int              `json:"active_connections"`
	Period                string           `json:"period"` // "24h", "7d", "30d"
}

// GetUsage handles GET /admin/usage
func (h *Handler) GetUsage(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	usage, err := h.collectUsageStats(r.Context(), period)
	if err != nil {
		log.Printf("Admin: GetUsage error: %v", err)
		http.Error(w, "Failed to collect usage stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(usage)
}

// collectUsageStats aggregates usage statistics from various sources
func (h *Handler) collectUsageStats(ctx context.Context, period string) (*UsageStats, error) {
	stats := &UsageStats{
		Timestamp:             time.Now().UTC(),
		TotalRequests:         0,
		TotalTokensProcessed:  0,
		TotalCostUSD:          0.0,
		RequestsByModel:       make(map[string]int64),
		RequestsByProvider:    make(map[string]int64),
		RequestsByRoute:       make(map[string]int64),
		ErrorsByType:          make(map[string]int64),
		AverageResponseTimeMs: 0.0,
		ActiveConnections:     0,
		Period:                period,
	}

	if stats.Period == "" {
		stats.Period = "24h" // Default period
	}

	// Try to collect real statistics from available sources
	if err := h.aggregateProviderStats(ctx, stats); err != nil {
		log.Printf("Admin: Warning - failed to aggregate provider stats: %v", err)
	}

	if err := h.aggregateRouteStats(ctx, stats); err != nil {
		log.Printf("Admin: Warning - failed to aggregate route stats: %v", err)
	}

	// TODO: Integrate with actual telemetry/metrics collection.
	// This function should ideally query a dedicated metrics backend (e.g., Prometheus via its API,
	// or a database populated by a metrics pipeline) that aggregates data from the
	// Prometheus metrics exposed by the gateway's /metrics endpoint (telemetry.MetricsHandler()).
	// Direct querying of live prometheus.CounterVec/HistogramVec from telemetry package here
	// for arbitrary time ranges (period) and labels is complex and not the primary design
	// of the Prometheus client library.
	//
	// For now, this function returns zeroed or minimally populated stats.
	// The `aggregateProviderStats` and `aggregateRouteStats` initialize maps but don't
	// populate them with actual request counts from metrics.

	if h.metricsClient != nil {
		endTime := time.Now()
		// var startTime time.Time // Not used for instant queries with duration selectors
		var promDuration string

		switch period {
		case "7d":
			// startTime = endTime.Add(-7 * 24 * time.Hour)
			promDuration = "7d"
		case "30d":
			// startTime = endTime.Add(-30 * 24 * time.Hour)
			promDuration = "30d"
		case "24h":
			fallthrough
		default:
			// startTime = endTime.Add(-24 * time.Hour)
			promDuration = "1d" // Prometheus expects 'd' for day
		}
		// queryRange := prometheusv1.Range{Start: startTime, End: endTime, Step: time.Minute} // Step can be adjusted. Not used with Query.

		// Query TotalRequests
		totalRequestsQuery := fmt.Sprintf("sum(increase(http_requests_total[%s]))", promDuration)
		val, warnings, err := h.metricsClient.Query(ctx, totalRequestsQuery, endTime)
		if err != nil {
			log.Printf("Admin: Error querying total requests: %v", err)
		} else {
			if len(warnings) > 0 {
				log.Printf("Admin: Warnings querying total requests: %v", warnings)
			}
			if val != nil && val.Type() == pmodel.ValVector {
				if vec, ok := val.(pmodel.Vector); ok && len(vec) > 0 {
					stats.TotalRequests = int64(vec[0].Value)
				}
			}
		}

		// Query AverageResponseTimeMs
		avgResponseTimeQuery := fmt.Sprintf("(sum(rate(http_request_duration_seconds_sum[%s])) / sum(rate(http_request_duration_seconds_count[%s]))) * 1000", promDuration, promDuration)
		val, warnings, err = h.metricsClient.Query(ctx, avgResponseTimeQuery, endTime)
		if err != nil {
			log.Printf("Admin: Error querying average response time: %v", err)
		} else {
			if len(warnings) > 0 {
				log.Printf("Admin: Warnings querying average response time: %v", warnings)
			}
			if val != nil && val.Type() == pmodel.ValVector {
				if vec, ok := val.(pmodel.Vector); ok && len(vec) > 0 {
					stats.AverageResponseTimeMs = float64(vec[0].Value)
				}
			}
		}

		// Query RequestsByRoute (using handler label as a proxy for route)
		requestsByRouteQuery := fmt.Sprintf("sum(increase(http_requests_total{handler!=\"\"}[%s])) by (handler)", promDuration)
		val, warnings, err = h.metricsClient.Query(ctx, requestsByRouteQuery, endTime)
		if err != nil {
			log.Printf("Admin: Error querying requests by route: %v", err)
		} else {
			if len(warnings) > 0 {
				log.Printf("Admin: Warnings querying requests by route: %v", warnings)
			}
			if val != nil && val.Type() == pmodel.ValVector {
				if vec, ok := val.(pmodel.Vector); ok {
					for _, sample := range vec {
						handlerName := string(sample.Metric["handler"])
						stats.RequestsByRoute[handlerName] = int64(sample.Value)
					}
				}
			}
		}

		// Query ErrorsByType (approximated by HTTP status codes 4xx, 5xx)
		// This is a simplified example. A dedicated error type label would be better.
		errorsQuery := fmt.Sprintf("sum(increase(http_requests_total{code=~\"^[45]..\"}[%s])) by (code)", promDuration)
		val, warnings, err = h.metricsClient.Query(ctx, errorsQuery, endTime)
		if err != nil {
			log.Printf("Admin: Error querying error counts: %v", err)
		} else {
			if len(warnings) > 0 {
				log.Printf("Admin: Warnings querying error counts: %v", warnings)
			}
			if val != nil && val.Type() == pmodel.ValVector {
				if vec, ok := val.(pmodel.Vector); ok {
					for _, sample := range vec {
						errorCode := string(sample.Metric["code"])
						stats.ErrorsByType[errorCode] += int64(sample.Value) // Summing up, could be more granular
					}
				}
			}
		}

		// Metrics for TotalTokensProcessed, TotalCostUSD, RequestsByModel, RequestsByProvider, ActiveConnections
		// are not yet defined in telemetry.go. These would require new Prometheus metrics and PromQL queries.
		log.Printf("Admin: Note - Metrics for tokens, cost, model/provider breakdown, and active connections are placeholders as underlying Prometheus metrics are not yet defined.")

	} else {
		log.Printf("Admin: MetricsClient not configured; cannot query Prometheus for dashboard metrics.")
	}

	return stats, nil
}

// aggregateProviderStats collects statistics per provider
func (h *Handler) aggregateProviderStats(ctx context.Context, stats *UsageStats) error {
	allProviderData, err := h.store.List(ctx, "providers/")
	if err != nil {
		return fmt.Errorf("failed to list providers: %w", err)
	}

	for _, data := range allProviderData {
		var pCfg config.ProviderConfig
		if json.Unmarshal(data, &pCfg) == nil {
			if stats.RequestsByProvider[pCfg.ID] == 0 {
				stats.RequestsByProvider[pCfg.ID] = 0
			}
		}
	}

	return nil
}

// aggregateRouteStats collects statistics per route
func (h *Handler) aggregateRouteStats(ctx context.Context, stats *UsageStats) error {
	allRouteData, err := h.store.List(ctx, "routes/")
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	for _, data := range allRouteData {
		var rCfg config.RouteConfig
		if json.Unmarshal(data, &rCfg) == nil {
			if stats.RequestsByRoute[rCfg.ID] == 0 {
				stats.RequestsByRoute[rCfg.ID] = 0
			}
		}
	}

	return nil
}

// --- Settings Handlers ---

// GlobalSettings represents the gateway's global settings
type GlobalSettings struct {
	DefaultTimeoutMs     int                    `json:"default_timeout_ms"`
	DefaultRetryAttempts int                    `json:"default_retry_attempts"`
	LogLevel             string                 `json:"log_level"`
	TelemetryEnabled     bool                   `json:"telemetry_enabled"`
	PluginsEnabled       bool                   `json:"plugins_enabled"`
	RateLimiting         *RateLimitingSettings  `json:"rate_limiting,omitempty"`
	Security             *SecuritySettings      `json:"security,omitempty"`
	Features             map[string]interface{} `json:"features,omitempty"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

type RateLimitingSettings struct {
	Enabled           bool `json:"enabled"`
	DefaultRPM        int  `json:"default_rpm"`         // Requests per minute
	DefaultTPM        int  `json:"default_tpm"`         // Tokens per minute
	BurstMultiplier   int  `json:"burst_multiplier"`    // Allow bursts up to N times the rate
	WindowSizeMinutes int  `json:"window_size_minutes"` // Rate limiting window
}

type SecuritySettings struct {
	RequireAPIKey       bool     `json:"require_api_key"`
	AllowedOrigins      []string `json:"allowed_origins,omitempty"`
	EncryptionEnabled   bool     `json:"encryption_enabled"`
	AuditLoggingEnabled bool     `json:"audit_logging_enabled"`
}

// GetSettings handles GET /admin/settings
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.getGlobalSettings(r.Context())
	if err != nil {
		log.Printf("Admin: GetSettings error: %v", err)
		http.Error(w, "Failed to get settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// UpdateSettings handles PATCH /admin/settings
func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var updateReq GlobalSettings
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	settings, err := h.updateGlobalSettings(r.Context(), &updateReq)
	if err != nil {
		log.Printf("Admin: UpdateSettings error: %v", err)
		http.Error(w, "Failed to update settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// getGlobalSettings retrieves current global settings
func (h *Handler) getGlobalSettings(ctx context.Context) (*GlobalSettings, error) {
	currentConfig := h.configMgr.GetCurrentConfig()
	if currentConfig == nil {
		return nil, fmt.Errorf("current configuration not available")
	}

	settingsData, err := h.store.Get(ctx, "settings/global")
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("failed to get stored settings: %w", err)
	}

	settings := &GlobalSettings{
		DefaultTimeoutMs:     currentConfig.Settings.DefaultTimeoutMs,
		DefaultRetryAttempts: currentConfig.Settings.DefaultRetryAttempts,
		LogLevel:             "info", // Default
		TelemetryEnabled:     true,   // Default
		PluginsEnabled:       true,   // Default
		RateLimiting: &RateLimitingSettings{
			Enabled:           false, // Default
			DefaultRPM:        1000,  // Default
			DefaultTPM:        10000, // Default
			BurstMultiplier:   2,     // Default
			WindowSizeMinutes: 1,     // Default
		},
		Security: &SecuritySettings{
			RequireAPIKey:       true,          // Default
			AllowedOrigins:      []string{"*"}, // Default (unsafe for prod)
			EncryptionEnabled:   true,          // Default
			AuditLoggingEnabled: false,         // Default
		},
		Features:  make(map[string]interface{}),
		UpdatedAt: time.Now().UTC(),
	}

	if settingsData != nil {
		var storedSettings GlobalSettings
		if err := json.Unmarshal(settingsData, &storedSettings); err == nil {
			if storedSettings.LogLevel != "" {
				settings.LogLevel = storedSettings.LogLevel
			}
			settings.TelemetryEnabled = storedSettings.TelemetryEnabled
			settings.PluginsEnabled = storedSettings.PluginsEnabled
			if storedSettings.RateLimiting != nil {
				settings.RateLimiting = storedSettings.RateLimiting
			}
			if storedSettings.Security != nil {
				settings.Security = storedSettings.Security
			}
			if storedSettings.Features != nil {
				settings.Features = storedSettings.Features
			}
			settings.UpdatedAt = storedSettings.UpdatedAt
		}
	}

	return settings, nil
}

// updateGlobalSettings updates and persists global settings
func (h *Handler) updateGlobalSettings(ctx context.Context, updateReq *GlobalSettings) (*GlobalSettings, error) {
	currentSettings, err := h.getGlobalSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current settings: %w", err)
	}

	if updateReq.DefaultTimeoutMs > 0 {
		currentSettings.DefaultTimeoutMs = updateReq.DefaultTimeoutMs
	}
	if updateReq.DefaultRetryAttempts >= 0 {
		currentSettings.DefaultRetryAttempts = updateReq.DefaultRetryAttempts
	}
	if updateReq.LogLevel != "" {
		validLevels := []string{"debug", "info", "warn", "error"}
		isValid := false
		for _, level := range validLevels {
			if updateReq.LogLevel == level {
				isValid = true
				break
			}
		}
		if !isValid {
			return nil, fmt.Errorf("invalid log level: %s. Valid levels: %v", updateReq.LogLevel, validLevels)
		}
		currentSettings.LogLevel = updateReq.LogLevel
	}

	currentSettings.TelemetryEnabled = updateReq.TelemetryEnabled
	currentSettings.PluginsEnabled = updateReq.PluginsEnabled

	if updateReq.RateLimiting != nil {
		currentSettings.RateLimiting = updateReq.RateLimiting
	}
	if updateReq.Security != nil {
		currentSettings.Security = updateReq.Security
	}
	if updateReq.Features != nil {
		currentSettings.Features = updateReq.Features
	}

	currentSettings.UpdatedAt = time.Now().UTC()

	// Persist the admin.GlobalSettings to its specific key
	settingsData, err := json.Marshal(currentSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal global settings: %w", err)
	}
	if err := h.store.Set(ctx, "settings/global", settingsData); err != nil {
		return nil, fmt.Errorf("failed to store global settings: %w", err)
	}

	// Now, update the GatewaySettings within the main RuntimeConfig
	// to ensure ConfigManager picks up changes relevant to its subscribers (e.g., xDS).
	fullRuntimeConfig := h.configMgr.GetCurrentConfig()
	if fullRuntimeConfig == nil {
		// This might happen if configMgr hasn't loaded config yet, though unlikely if getGlobalSettings succeeded.
		log.Printf("Admin: Warning - could not retrieve full RuntimeConfig to update GatewaySettings part; ConfigManager might not be notified of settings changes for DefaultTimeoutMs/DefaultRetryAttempts.")
	} else {
		madeChangesToRuntimeCfg := false
		if fullRuntimeConfig.Settings.DefaultTimeoutMs != currentSettings.DefaultTimeoutMs {
			fullRuntimeConfig.Settings.DefaultTimeoutMs = currentSettings.DefaultTimeoutMs
			madeChangesToRuntimeCfg = true
		}
		if fullRuntimeConfig.Settings.DefaultRetryAttempts != currentSettings.DefaultRetryAttempts {
			fullRuntimeConfig.Settings.DefaultRetryAttempts = currentSettings.DefaultRetryAttempts
			madeChangesToRuntimeCfg = true
		}

		// Other fields from admin.GlobalSettings (LogLevel, TelemetryEnabled, etc.)
		// are not part of config.GatewaySettings and thus not directly part of RuntimeConfig.Settings.
		// Their updates might require different mechanisms (e.g., direct re-init of logger/telemetry services,
		// or an expansion of config.GatewaySettings if they are to be managed via RuntimeConfig and xDS).
		// For now, only DefaultTimeoutMs and DefaultRetryAttempts are propagated to RuntimeConfig.Settings.

		if madeChangesToRuntimeCfg {
			fullRuntimeConfig.LastUpdated = time.Now().UTC() // Update timestamp for the whole RuntimeConfig
			runtimeConfigData, marshalErr := json.Marshal(fullRuntimeConfig)
			if marshalErr != nil {
				log.Printf("Admin: Error marshalling full RuntimeConfig for update: %v. ConfigManager may not be notified.", marshalErr)
				// Decide if this error should be returned to the client or just logged.
				// For now, we proceed to return currentSettings, but the ConfigManager notification might have failed.
			} else {
				// The key "config/runtime/current" is used by ConfigManager internally.
				// Ensure this constant is correctly referenced if it's exported from config package,
				// otherwise use the string literal carefully.
				const runtimeConfigKey = "config/runtime/current" // As defined in config/config.go (not exported)
				if errStoreRuntime := h.store.Set(ctx, runtimeConfigKey, runtimeConfigData); errStoreRuntime != nil {
					log.Printf("Admin: Error storing updated RuntimeConfig to '%s': %v. ConfigManager may not be notified.", runtimeConfigKey, errStoreRuntime)
				} else {
					log.Printf("Admin: Updated RuntimeConfig in store ('%s') to notify ConfigManager of settings changes.", runtimeConfigKey)
				}
			}
		}
	}

	// The TODO for explicit notification is removed as changes to "config/runtime/current"
	// (if relevant parts of GlobalSettings are mapped to RuntimeConfig.Settings)
	// will be picked up by ConfigManager's watch mechanism.
	log.Printf("Admin: Global settings updated successfully (admin store and potentially runtime config).")
	return currentSettings, nil
}

// --- Provider Handlers ---
func (h *Handler) CreateProvider(w http.ResponseWriter, r *http.Request) {
	var req config.ProviderConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Type == "" {
		http.Error(w, "Provider name and type are required", http.StatusBadRequest)
		return
	}

	req.ID = uuid.NewString()
	req.CreatedAt = time.Now().UTC()
	req.UpdatedAt = time.Now().UTC()
	if req.Status == "" {
		req.Status = "active"
	}

	providerData, err := json.Marshal(req)
	if err != nil {
		http.Error(w, "Failed to marshal provider data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	storeKey := "providers/" + req.ID
	if err := h.store.Set(r.Context(), storeKey, providerData); err != nil {
		http.Error(w, "Failed to save provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Admin: Created Provider: ID=%s, Name=%s, Type=%s", req.ID, req.Name, req.Type)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

func (h *Handler) ListProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queryParams := r.URL.Query()
	limit, offset := getPaginationParams(queryParams)
	filterType := queryParams.Get("type")

	allProviderData, err := h.store.List(ctx, "providers/")
	if err != nil {
		http.Error(w, "Failed to list providers: "+err.Error(), http.StatusInternalServerError)
		return
	}

	allProviders := make([]config.ProviderConfig, 0, len(allProviderData))
	for _, data := range allProviderData {
		var pCfg config.ProviderConfig
		if json.Unmarshal(data, &pCfg) == nil {
			allProviders = append(allProviders, pCfg)
		}
	}

	filteredProviders := allProviders
	if filterType != "" {
		filteredProviders = make([]config.ProviderConfig, 0)
		for _, p := range allProviders {
			if string(p.Type) == filterType {
				filteredProviders = append(filteredProviders, p)
			}
		}
	}

	response := struct {
		Providers  []config.ProviderConfig `json:"providers"`
		TotalCount int                     `json:"total_count"`
		Offset     int                     `json:"offset"`
		Limit      int                     `json:"limit"`
	}{
		Providers:  paginate(filteredProviders, offset, limit),
		TotalCount: len(filteredProviders),
		Offset:     offset,
		Limit:      limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) GetProvider(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")
	providerData, err := h.store.Get(r.Context(), "providers/"+providerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Provider not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to get provider: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	var pCfg config.ProviderConfig
	if json.Unmarshal(providerData, &pCfg) != nil {
		http.Error(w, "Failed to unmarshal provider data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pCfg)
}

func (h *Handler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")
	storeKey := "providers/" + providerID

	existingData, err := h.store.Get(r.Context(), storeKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Provider not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to get existing provider: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	var existingProvider config.ProviderConfig
	if json.Unmarshal(existingData, &existingProvider) != nil {
		http.Error(w, "Failed to unmarshal existing provider data", http.StatusInternalServerError)
		return
	}

	var updatedReq config.ProviderConfig
	if json.NewDecoder(r.Body).Decode(&updatedReq) != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if updatedReq.Name == "" || updatedReq.Type == "" {
		http.Error(w, "Provider name and type are required", http.StatusBadRequest)
		return
	}

	if updatedReq.ID != "" && updatedReq.ID != providerID {
		http.Error(w, "Provider ID in body does not match ID in path", http.StatusBadRequest)
		return
	}

	updatedProvider := existingProvider
	updatedProvider.Name = updatedReq.Name
	updatedProvider.Type = updatedReq.Type
	updatedProvider.Status = updatedReq.Status
	if updatedProvider.Status == "" {
		updatedProvider.Status = "active"
	}
	updatedProvider.CredentialsSecretID = updatedReq.CredentialsSecretID
	updatedProvider.LLMConfig = updatedReq.LLMConfig
	updatedProvider.MCPToolConfig = updatedReq.MCPToolConfig
	updatedProvider.A2APlatformConfig = updatedReq.A2APlatformConfig
	updatedProvider.UpdatedAt = time.Now().UTC()

	updatedData, err := json.Marshal(updatedProvider)
	if err != nil {
		http.Error(w, "Failed to marshal updated provider data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.store.Set(r.Context(), storeKey, updatedData) != nil {
		http.Error(w, "Failed to save updated provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedProvider)
}

func (h *Handler) DeleteProvider(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")
	storeKey := "providers/" + providerID
	force := r.URL.Query().Get("force") == "true"

	if !force {
		currentConfig := h.configMgr.GetCurrentConfig()
		if currentConfig != nil {
			for _, model := range currentConfig.Models {
				if model.ProviderID == providerID {
					http.Error(w, fmt.Sprintf("Cannot delete provider ID '%s': used by model '%s'. Use force=true.", providerID, model.ID), http.StatusConflict)
					return
				}
			}
			for _, route := range currentConfig.Routes {
				if route.Protocol == config.ProtocolHTTPLLM {
					for _, target := range route.Targets {
						for _, model := range currentConfig.Models {
							if model.ID == target.Ref && model.ProviderID == providerID {
								http.Error(w, fmt.Sprintf("Cannot delete provider ID '%s': used by route '%s' via model '%s'. Use force=true.", providerID, route.ID, model.ID), http.StatusConflict)
								return
							}
						}
					}
				} else if route.Protocol == config.ProtocolMCPTool {
					for _, target := range route.Targets {
						for _, tool := range currentConfig.Tools {
							if tool.ID == target.Ref && tool.ProviderID == providerID {
								http.Error(w, fmt.Sprintf("Cannot delete provider ID '%s': used by route '%s' via tool '%s'. Use force=true.", providerID, route.ID, tool.ID), http.StatusConflict)
								return
							}
						}
					}
				} else if route.Protocol == config.ProtocolA2ATask {
					for _, target := range route.Targets {
						for _, agent := range currentConfig.Agents {
							if agent.ID == target.Ref && agent.ProviderID == providerID {
								http.Error(w, fmt.Sprintf("Cannot delete provider ID '%s': used by route '%s' via agent '%s'. Use force=true.", providerID, route.ID, agent.ID), http.StatusConflict)
								return
							}
						}
					}
				}
			}
		}
	}

	if err := h.store.Delete(r.Context(), storeKey); err != nil {
		http.Error(w, "Failed to delete provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Model Handlers ---
func (h *Handler) CreateModel(w http.ResponseWriter, r *http.Request) {
	var req config.ModelConfig
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.ProviderID == "" || req.UpstreamModelName == "" {
		http.Error(w, "Model ID, ProviderID, UpstreamModelName required", http.StatusBadRequest)
		return
	}

	_, err := h.store.Get(r.Context(), "providers/"+req.ProviderID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "ProviderID not found", http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to validate ProviderID", http.StatusInternalServerError)
		}
		return
	}

	storeKey := "models/" + req.ID
	_, errGet := h.store.Get(r.Context(), storeKey)
	if errGet == nil {
		http.Error(w, "Model ID already exists", http.StatusConflict)
		return
	}
	if !errors.Is(errGet, store.ErrNotFound) {
		http.Error(w, "Failed to check existing model", http.StatusInternalServerError)
		return
	}

	req.CreatedAt = time.Now().UTC()
	req.UpdatedAt = time.Now().UTC()
	if req.Status == "" {
		req.Status = "active"
	}

	modelData, err := json.Marshal(req)
	if err != nil {
		http.Error(w, "Failed to marshal model", http.StatusInternalServerError)
		return
	}

	if h.store.Set(r.Context(), storeKey, modelData) != nil {
		http.Error(w, "Failed to save model", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

func (h *Handler) ListModels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queryParams := r.URL.Query()
	limit, offset := getPaginationParams(queryParams)
	filterProviderID := queryParams.Get("provider_id")

	allModelData, err := h.store.List(ctx, "models/")
	if err != nil {
		http.Error(w, "Failed to list models", http.StatusInternalServerError)
		return
	}

	allModels := make([]config.ModelConfig, 0, len(allModelData))
	for _, data := range allModelData {
		var mCfg config.ModelConfig
		if json.Unmarshal(data, &mCfg) == nil {
			allModels = append(allModels, mCfg)
		}
	}

	filteredModels := allModels
	if filterProviderID != "" {
		filteredModels = make([]config.ModelConfig, 0)
		for _, m := range allModels {
			if m.ProviderID == filterProviderID {
				filteredModels = append(filteredModels, m)
			}
		}
	}

	response := struct {
		Models     []config.ModelConfig `json:"models"`
		TotalCount int                  `json:"total_count"`
		Offset     int                  `json:"offset"`
		Limit      int                  `json:"limit"`
	}{
		Models:     paginate(filteredModels, offset, limit),
		TotalCount: len(filteredModels),
		Offset:     offset,
		Limit:      limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) GetModel(w http.ResponseWriter, r *http.Request) {
	modelID := chi.URLParam(r, "modelID")
	modelData, err := h.store.Get(r.Context(), "models/"+modelID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Model not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to get model", http.StatusInternalServerError)
		}
		return
	}

	var mCfg config.ModelConfig
	if json.Unmarshal(modelData, &mCfg) != nil {
		http.Error(w, "Failed to unmarshal model", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mCfg)
}

func (h *Handler) UpdateModel(w http.ResponseWriter, r *http.Request) {
	modelID := chi.URLParam(r, "modelID")
	storeKey := "models/" + modelID

	existingData, err := h.store.Get(r.Context(), storeKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Model not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to get model", http.StatusInternalServerError)
		}
		return
	}

	var existingModel config.ModelConfig
	if json.Unmarshal(existingData, &existingModel) != nil {
		http.Error(w, "Failed to unmarshal model", http.StatusInternalServerError)
		return
	}

	var updatedReq config.ModelConfig
	if err := json.NewDecoder(r.Body).Decode(&updatedReq); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Basic validation
	if updatedReq.ID != "" && updatedReq.ID != modelID {
		http.Error(w, "Model ID in body does not match ID in path", http.StatusBadRequest)
		return
	}
	if updatedReq.ProviderID == "" || updatedReq.UpstreamModelName == "" {
		http.Error(w, "ProviderID and UpstreamModelName are required", http.StatusBadRequest)
		return
	}

	// Validate ProviderID exists
	_, err = h.store.Get(r.Context(), "providers/"+updatedReq.ProviderID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, fmt.Sprintf("ProviderID '%s' not found", updatedReq.ProviderID), http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to validate ProviderID: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Apply updates
	updatedModel := existingModel
	updatedModel.ProviderID = updatedReq.ProviderID
	updatedModel.UpstreamModelName = updatedReq.UpstreamModelName

	if updatedReq.Status != "" {
		updatedModel.Status = updatedReq.Status
	}
	if updatedReq.Version != "" { // Version is optional
		updatedModel.Version = updatedReq.Version
	}
	if updatedReq.ContextWindow > 0 {
		updatedModel.ContextWindow = updatedReq.ContextWindow
	}
	if updatedReq.InputPricingPerToken > 0 { // Check for > 0 as it's a float
		updatedModel.InputPricingPerToken = updatedReq.InputPricingPerToken
	}
	if updatedReq.OutputPricingPerToken > 0 { // Check for > 0
		updatedModel.OutputPricingPerToken = updatedReq.OutputPricingPerToken
	}
	if updatedReq.InputPricingPerSecond > 0 {
		updatedModel.InputPricingPerSecond = updatedReq.InputPricingPerSecond
	}
	if updatedReq.OutputPricingPerSecond > 0 {
		updatedModel.OutputPricingPerSecond = updatedReq.OutputPricingPerSecond
	}
	if updatedReq.Metadata != nil {
		updatedModel.Metadata = updatedReq.Metadata
	}
	updatedModel.UpdatedAt = time.Now().UTC()

	modelData, err := json.Marshal(updatedModel)
	if err != nil {
		http.Error(w, "Failed to marshal updated model: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.store.Set(r.Context(), storeKey, modelData); err != nil {
		http.Error(w, "Failed to save updated model: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedModel)
}

// --- IAM: Role Handlers ---

// CreateRoleRequest defines the payload for creating a new role.
type CreateRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"` // Array of permission strings
}

// CreateRole handles POST /admin/iam/roles
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Role name is required", http.StatusBadRequest)
		return
	}
	if len(req.Permissions) == 0 {
		http.Error(w, "Role must have at least one permission", http.StatusBadRequest)
		return
	}

	for _, pStr := range req.Permissions {
		if !isValidPermissionFormatHelper(pStr) {
			http.Error(w, fmt.Sprintf("Invalid permission format: '%s'. Must be 'resource:action'.", pStr), http.StatusBadRequest)
			return
		}
		// TODO: Optionally, check against a list of known/valid permissions via h.iamService if such a method exists.
	}

	roleToCreate := &iam.Role{
		Name:        req.Name,
		Description: req.Description,
		Permissions: make([]iam.Permission, len(req.Permissions)),
	}
	for i, pStr := range req.Permissions {
		roleToCreate.Permissions[i] = iam.Permission(pStr)
	}

	// Assuming h.iamService will have a CreateRole method.
	// This method would typically handle storing the role.
	// The iam.Role struct itself doesn't have ID, CreatedAt, UpdatedAt.
	// The iam.Service would manage how roles are stored and identified (likely by Name).
	createdRole, err := h.iamService.CreateRole(r.Context(), roleToCreate)
	if err != nil {
		// Handle specific errors from iamService, e.g., role already exists
		if errors.Is(err, iam.ErrRoleAlreadyExists) { // Assuming iam.ErrRoleAlreadyExists is defined
			http.Error(w, "Role with this name already exists: "+err.Error(), http.StatusConflict)
		} else {
			log.Printf("Admin: CreateRole error: %v", err)
			http.Error(w, "Failed to create role: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Created Role: Name=%s", createdRole.Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdRole)
}

// ListRoles handles GET /admin/iam/roles
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.iamService.ListRoles(r.Context())
	if err != nil {
		log.Printf("Admin: ListRoles error: %v", err)
		http.Error(w, "Failed to list roles: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare response, could add pagination info if ListRoles supported it
	response := struct {
		Roles []*iam.Role `json:"roles"`
		Count int         `json:"count"`
	}{
		Roles: roles,
		Count: len(roles),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetRole handles GET /admin/iam/roles/{roleName}
func (h *Handler) GetRole(w http.ResponseWriter, r *http.Request) {
	roleName := chi.URLParam(r, "roleName")
	if roleName == "" {
		http.Error(w, "Role name parameter is required", http.StatusBadRequest)
		return
	}

	role, err := h.iamService.GetRole(r.Context(), roleName)
	if err != nil {
		if errors.Is(err, iam.ErrRoleNotFound) {
			http.Error(w, "Role not found: "+roleName, http.StatusNotFound)
		} else {
			log.Printf("Admin: GetRole error for '%s': %v", roleName, err)
			http.Error(w, "Failed to get role: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(role)
}

// UpdateRoleRequest defines the payload for updating an existing role.
// Name is not updatable via this request; it's taken from the URL.
type UpdateRoleRequest struct {
	Description *string  `json:"description,omitempty"` // Pointer to distinguish between empty string and not provided
	Permissions []string `json:"permissions,omitempty"` // Pointer to distinguish between empty slice and not provided
}

// UpdateRole handles PATCH /admin/iam/roles/{roleName}
func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	roleName := chi.URLParam(r, "roleName")
	if roleName == "" {
		http.Error(w, "Role name parameter is required", http.StatusBadRequest)
		return
	}

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Construct the iam.Role for update.
	// Only fields present in UpdateRoleRequest will be used by iamService.UpdateRole.
	roleUpdatePayload := &iam.Role{
		Name: roleName, // Set Name for clarity, though service uses path param
	}

	// Apply partial updates: only set fields if they are present in the request.
	// For Description, if req.Description is nil, it means client didn't send it.
	// If client sent `{"description": ""}`, then *req.Description would be an empty string.
	// If client sent `{"description": "new desc"}`, *req.Description is "new desc".
	// The iam.Service.UpdateRole logic needs to handle this (e.g., update if field in payload is non-nil).
	// My current iam.Service.UpdateRole updates if roleUpdate.Description != "" and roleUpdate.Permissions != nil.
	// This means to clear permissions, client must send "permissions": []. To clear description, "description": "".

	if req.Description != nil {
		roleUpdatePayload.Description = *req.Description
	}
	// If req.Permissions is nil, it means the client did not include the 'permissions' field in the PATCH request.
	// If req.Permissions is an empty slice ([]), it means the client wants to clear all permissions.
	// If req.Permissions has items, it means the client wants to set these new permissions.
	// The iam.Service.UpdateRole handles `roleUpdate.Permissions != nil`.
	if req.Permissions != nil {
		for _, pStr := range req.Permissions {
			if !isValidPermissionFormatHelper(pStr) {
				http.Error(w, fmt.Sprintf("Invalid permission format in update: '%s'. Must be 'resource:action'.", pStr), http.StatusBadRequest)
				return
			}
			// TODO: Optionally, check against a list of known/valid permissions.
		}
		roleUpdatePayload.Permissions = make([]iam.Permission, len(req.Permissions))
		for i, pStr := range req.Permissions {
			roleUpdatePayload.Permissions[i] = iam.Permission(pStr)
		}
	}

	updatedRole, err := h.iamService.UpdateRole(r.Context(), roleName, roleUpdatePayload)
	if err != nil {
		if errors.Is(err, iam.ErrRoleNotFound) {
			http.Error(w, "Role not found: "+roleName, http.StatusNotFound)
		} else {
			log.Printf("Admin: UpdateRole error for '%s': %v", roleName, err)
			http.Error(w, "Failed to update role: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Updated Role: Name=%s", updatedRole.Name)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedRole)
}

// DeleteRole handles DELETE /admin/iam/roles/{roleName}
func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	roleName := chi.URLParam(r, "roleName")
	if roleName == "" {
		http.Error(w, "Role name parameter is required", http.StatusBadRequest)
		return
	}

	// Define built-in roles that cannot be deleted.
	// This list should ideally be managed centrally or come from a configuration/constant.
	builtInRoles := map[string]bool{
		"admin":  true,
		"viewer": true,
		// Add any other critical predefined roles here
	}

	if builtInRoles[roleName] {
		http.Error(w, fmt.Sprintf("Built-in role '%s' cannot be deleted.", roleName), http.StatusBadRequest)
		return
	}

	err := h.iamService.DeleteRole(r.Context(), roleName)
	if err != nil {
		if errors.Is(err, iam.ErrRoleNotFound) {
			http.Error(w, "Role not found: "+roleName, http.StatusNotFound)
		} else {
			log.Printf("Admin: DeleteRole error for '%s': %v", roleName, err)
			http.Error(w, "Failed to delete role: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Deleted Role: Name=%s", roleName)
	w.WriteHeader(http.StatusNoContent)
}

// TODO: Add DeleteModel handler

// --- IAM: Group Handlers ---

// CreateGroupRequest defines the payload for creating a new group.
type CreateGroupRequest struct {
	Name      string   `json:"name"`
	MemberIDs []string `json:"member_ids,omitempty"` // Optional list of user IDs
}

// CreateGroup handles POST /admin/iam/groups
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var req CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Group name is required", http.StatusBadRequest)
		return
	}

	if len(req.MemberIDs) > 0 {
		for _, memberID := range req.MemberIDs {
			_, err := h.iamService.GetUser(r.Context(), memberID)
			if err != nil {
				if errors.Is(err, iam.ErrUserNotFound) {
					http.Error(w, fmt.Sprintf("Invalid member ID: User with ID '%s' not found.", memberID), http.StatusBadRequest)
				} else {
					log.Printf("Admin: CreateGroup - Error validating member ID '%s': %v", memberID, err)
					http.Error(w, "Failed to validate member IDs: "+err.Error(), http.StatusInternalServerError)
				}
				return
			}
		}
	}

	groupToCreate := &iam.Group{
		Name:      req.Name,
		MemberIDs: req.MemberIDs, // Will be nil if not provided, which is fine
	}

	createdGroup, err := h.iamService.CreateGroup(r.Context(), groupToCreate)
	if err != nil {
		if errors.Is(err, iam.ErrGroupAlreadyExists) {
			http.Error(w, "Group with this name already exists: "+err.Error(), http.StatusConflict)
		} else {
			log.Printf("Admin: CreateGroup error: %v", err)
			http.Error(w, "Failed to create group: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Created Group: Name=%s, ID=%s", createdGroup.Name, createdGroup.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdGroup)
}

// ListGroups handles GET /admin/iam/groups
func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	limit, offset := getPaginationParams(queryParams)
	nameFilter := queryParams.Get("name_filter") // Example filter for group name

	listOpts := iam.ListGroupOptions{
		Limit:      limit,
		Offset:     offset,
		NameFilter: nameFilter,
	}

	groups, totalCount, err := h.iamService.ListGroups(r.Context(), listOpts)
	if err != nil {
		log.Printf("Admin: ListGroups error: %v", err)
		http.Error(w, "Failed to list groups: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := struct {
		Groups     []*iam.Group `json:"groups"`
		TotalCount int          `json:"total_count"`
		Offset     int          `json:"offset"`
		Limit      int          `json:"limit"`
	}{
		Groups:     groups, // This is already paginated by the service
		TotalCount: totalCount,
		Offset:     offset,
		Limit:      limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetGroup handles GET /admin/iam/groups/{groupID}
func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		http.Error(w, "Group ID parameter is required", http.StatusBadRequest)
		return
	}

	group, err := h.iamService.GetGroup(r.Context(), groupID)
	if err != nil {
		if errors.Is(err, iam.ErrGroupNotFound) {
			http.Error(w, "Group not found: "+groupID, http.StatusNotFound)
		} else {
			log.Printf("Admin: GetGroup error for ID '%s': %v", groupID, err)
			http.Error(w, "Failed to get group: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(group)
}

// UpdateGroupRequest defines the payload for updating an existing group.
// ID is taken from the URL. Name and MemberIDs can be updated.
type UpdateGroupRequest struct {
	Name      *string  `json:"name,omitempty"`       // Pointer to distinguish between empty string and not provided for update
	MemberIDs []string `json:"member_ids,omitempty"` // If nil, members are not updated. If empty slice, members are cleared.
}

// UpdateGroup handles PATCH /admin/iam/groups/{groupID}
func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		http.Error(w, "Group ID parameter is required", http.StatusBadRequest)
		return
	}

	var req UpdateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	groupUpdatePayload := &iam.Group{
		// ID is set by the service method based on groupID path param
		// Name and MemberIDs will be set if provided in req
	}

	if req.Name != nil {
		if *req.Name == "" {
			http.Error(w, "Group name cannot be empty if provided for update", http.StatusBadRequest)
			return
		}
		groupUpdatePayload.Name = *req.Name
	}
	// MemberIDs being nil in req means "don't update members".
	// MemberIDs being an empty slice `[]` means "clear all members".
	// MemberIDs being a slice with items means "set these members".
	// The iam.Service.UpdateGroup handles `groupUpdate.MemberIDs != nil`.
	if req.MemberIDs != nil {
		groupUpdatePayload.MemberIDs = req.MemberIDs
	}

	updatedGroup, err := h.iamService.UpdateGroup(r.Context(), groupID, groupUpdatePayload)
	if err != nil {
		if errors.Is(err, iam.ErrGroupNotFound) {
			http.Error(w, "Group not found: "+groupID, http.StatusNotFound)
		} else if errors.Is(err, iam.ErrGroupAlreadyExists) { // Name collision
			http.Error(w, "Group name conflict: "+err.Error(), http.StatusConflict)
		} else {
			log.Printf("Admin: UpdateGroup error for ID '%s': %v", groupID, err)
			http.Error(w, "Failed to update group: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Updated Group: Name=%s, ID=%s", updatedGroup.Name, updatedGroup.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedGroup)
}

// DeleteGroup handles DELETE /admin/iam/groups/{groupID}
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		http.Error(w, "Group ID parameter is required", http.StatusBadRequest)
		return
	}

	// Remove role bindings associated with this group before deleting the group.
	// Using "group" as principalType string, align with iam.CreateRoleBinding.
	if err := h.iamService.RemoveRoleBindingsForPrincipal(r.Context(), groupID, "group"); err != nil {
		// Log the error but proceed with group deletion attempt.
		// Depending on policy, this could be a hard failure.
		log.Printf("Admin: DeleteGroup - Failed to remove role bindings for group ID '%s': %v. Proceeding with group deletion.", groupID, err)
	}

	err := h.iamService.DeleteGroup(r.Context(), groupID)
	if err != nil {
		if errors.Is(err, iam.ErrGroupNotFound) {
			http.Error(w, "Group not found: "+groupID, http.StatusNotFound)
		} else {
			log.Printf("Admin: DeleteGroup error for ID '%s': %v", groupID, err)
			http.Error(w, "Failed to delete group: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Deleted Group: ID=%s", groupID)
	w.WriteHeader(http.StatusNoContent)
}

// ModifyGroupMembersRequest defines the payload for adding/removing members from a group.
type ModifyGroupMembersRequest struct {
	AddMemberIDs    []string `json:"add_member_ids,omitempty"`
	RemoveMemberIDs []string `json:"remove_member_ids,omitempty"`
}

// ModifyGroupMembers handles POST /admin/iam/groups/{groupID}/members
func (h *Handler) ModifyGroupMembers(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupID")
	if groupID == "" {
		http.Error(w, "Group ID parameter is required", http.StatusBadRequest)
		return
	}

	var req ModifyGroupMembersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.AddMemberIDs) == 0 && len(req.RemoveMemberIDs) == 0 {
		http.Error(w, "Either add_member_ids or remove_member_ids must be provided", http.StatusBadRequest)
		return
	}

	// Validate user IDs in AddMemberIDs
	if len(req.AddMemberIDs) > 0 {
		for _, memberID := range req.AddMemberIDs {
			_, err := h.iamService.GetUser(r.Context(), memberID)
			if err != nil {
				if errors.Is(err, iam.ErrUserNotFound) {
					http.Error(w, fmt.Sprintf("Invalid user ID to add: User with ID '%s' not found.", memberID), http.StatusBadRequest)
				} else {
					log.Printf("Admin: ModifyGroupMembers - Error validating user ID '%s' to add: %v", memberID, err)
					http.Error(w, "Failed to validate user IDs to add: "+err.Error(), http.StatusInternalServerError)
				}
				return
			}
		}
	}

	// Optional: Validate user IDs in RemoveMemberIDs.
	// Attempting to remove a non-existent user or a user not in the group might be a no-op at the service layer.
	// If strict validation is required (i.e., error if trying to remove a non-existent user), add it here.
	// For now, we let the service layer handle it (which currently doesn't validate existence for removal).

	updatedGroup, err := h.iamService.ModifyGroupMembers(r.Context(), groupID, req.AddMemberIDs, req.RemoveMemberIDs)
	if err != nil {
		if errors.Is(err, iam.ErrGroupNotFound) {
			http.Error(w, "Group not found: "+groupID, http.StatusNotFound)
		} else {
			log.Printf("Admin: ModifyGroupMembers error for ID '%s': %v", groupID, err)
			http.Error(w, "Failed to modify group members: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Modified members for Group ID: %s", groupID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedGroup) // Return the updated group
}

// --- IAM: RoleBinding Handlers ---

// CreateRoleBindingRequest defines the payload for creating a new role binding.
type CreateRoleBindingRequest struct {
	PrincipalType string     `json:"principal_type"` // "user", "group", or "serviceaccount"
	PrincipalID   string     `json:"principal_id"`
	RoleName      string     `json:"role_name"`
	Scope         *iam.Scope `json:"scope,omitempty"` // Optional scope
}

// CreateRoleBinding handles POST /admin/iam/bindings
func (h *Handler) CreateRoleBinding(w http.ResponseWriter, r *http.Request) {
	var req CreateRoleBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.PrincipalID == "" || req.PrincipalType == "" || req.RoleName == "" {
		http.Error(w, "principal_id, principal_type, and role_name are required", http.StatusBadRequest)
		return
	}

	bindingToCreate := &iam.RoleBinding{
		PrincipalType: req.PrincipalType,
		PrincipalID:   req.PrincipalID,
		RoleName:      req.RoleName,
	}
	if req.Scope != nil {
		bindingToCreate.Scope = *req.Scope
	} else {
		// Default to global scope if not provided
		bindingToCreate.Scope = iam.Scope{Type: "global"}
	}

	createdBinding, err := h.iamService.CreateRoleBinding(r.Context(), bindingToCreate)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidPrincipalType):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, iam.ErrUserNotFound):
			http.Error(w, "Principal (user) not found: "+req.PrincipalID, http.StatusNotFound)
		case errors.Is(err, iam.ErrGroupNotFound):
			http.Error(w, "Principal (group) not found: "+req.PrincipalID, http.StatusNotFound)
		case errors.Is(err, iam.ErrRoleNotFound):
			http.Error(w, "Role not found: "+req.RoleName, http.StatusNotFound)
		case errors.Is(err, iam.ErrRoleBindingAlreadyExists):
			http.Error(w, "This role binding already exists", http.StatusConflict)
		default:
			log.Printf("Admin: CreateRoleBinding error: %v", err)
			http.Error(w, "Failed to create role binding: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Created RoleBinding: ID=%s", createdBinding.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdBinding)
}

// ListRoleBindings handles GET /admin/iam/bindings
func (h *Handler) ListRoleBindings(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	limit, offset := getPaginationParams(queryParams)
	principalIDFilter := queryParams.Get("principal_id")
	principalTypeFilter := queryParams.Get("principal_type")
	roleNameFilter := queryParams.Get("role_name")

	listOpts := iam.ListRoleBindingOptions{
		Limit:               limit,
		Offset:              offset,
		PrincipalIDFilter:   principalIDFilter,
		PrincipalTypeFilter: principalTypeFilter,
		RoleNameFilter:      roleNameFilter,
	}

	bindings, totalCount, err := h.iamService.ListRoleBindings(r.Context(), listOpts)
	if err != nil {
		log.Printf("Admin: ListRoleBindings error: %v", err)
		http.Error(w, "Failed to list role bindings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := struct {
		RoleBindings []*iam.RoleBinding `json:"role_bindings"`
		TotalCount   int                `json:"total_count"`
		Offset       int                `json:"offset"`
		Limit        int                `json:"limit"`
	}{
		RoleBindings: bindings, // This is already paginated by the service
		TotalCount:   totalCount,
		Offset:       offset,
		Limit:        limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetRoleBinding handles GET /admin/iam/bindings/{bindingID}
func (h *Handler) GetRoleBinding(w http.ResponseWriter, r *http.Request) {
	bindingID := chi.URLParam(r, "bindingID")
	if bindingID == "" {
		http.Error(w, "Binding ID parameter is required", http.StatusBadRequest)
		return
	}

	binding, err := h.iamService.GetRoleBinding(r.Context(), bindingID)
	if err != nil {
		if errors.Is(err, iam.ErrRoleBindingNotFound) {
			http.Error(w, "Role binding not found: "+bindingID, http.StatusNotFound)
		} else {
			log.Printf("Admin: GetRoleBinding error for ID '%s': %v", bindingID, err)
			http.Error(w, "Failed to get role binding: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(binding)
}

// DeleteRoleBinding handles DELETE /admin/iam/bindings/{bindingID}
func (h *Handler) DeleteRoleBinding(w http.ResponseWriter, r *http.Request) {
	bindingID := chi.URLParam(r, "bindingID")
	if bindingID == "" {
		http.Error(w, "Binding ID parameter is required", http.StatusBadRequest)
		return
	}

	err := h.iamService.DeleteRoleBinding(r.Context(), bindingID)
	if err != nil {
		if errors.Is(err, iam.ErrRoleBindingNotFound) {
			http.Error(w, "Role binding not found: "+bindingID, http.StatusNotFound)
		} else {
			log.Printf("Admin: DeleteRoleBinding error for ID '%s': %v", bindingID, err)
			http.Error(w, "Failed to delete role binding: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Deleted RoleBinding: ID=%s", bindingID)
	w.WriteHeader(http.StatusNoContent)
}

// UpdateRoleBindingRequest defines the payload for updating a role binding.
// Currently, RoleBindings are mostly immutable in their core definition.
// This request is structured to allow potential future extensions (e.g., updating a description on the binding itself).
type UpdateRoleBindingRequest struct {
	// No updatable fields are defined for RoleBinding in the current iam.RoleBinding struct
	// other than what defines its identity (PrincipalType, PrincipalID, RoleName, Scope).
	// If, for example, a 'Description' or 'ExpiresAt' field were added to iam.RoleBinding,
	// it would be included here as a pointer to allow partial updates.
	// e.g., Description *string `json:"description,omitempty"`
}

// UpdateRoleBinding handles PATCH /admin/iam/bindings/{bindingID}
// Given the current structure of iam.RoleBinding, this is effectively a no-op
// or a re-validation, as core fields are immutable.
func (h *Handler) UpdateRoleBinding(w http.ResponseWriter, r *http.Request) {
	bindingID := chi.URLParam(r, "bindingID")
	if bindingID == "" {
		http.Error(w, "Binding ID parameter is required", http.StatusBadRequest)
		return
	}

	var req UpdateRoleBindingRequest // Currently empty, for future extension
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Construct an empty iam.RoleBinding for the update payload,
	// as the service method currently doesn't modify based on payload
	// for immutable fields.
	bindingUpdatePayload := &iam.RoleBinding{}

	// If UpdateRoleBindingRequest had fields, they would be mapped to bindingUpdatePayload here.
	// Example:
	// if req.Description != nil {
	// 	bindingUpdatePayload.Description = *req.Description // Assuming RoleBinding had a Description field
	// }

	updatedBinding, err := h.iamService.UpdateRoleBinding(r.Context(), bindingID, bindingUpdatePayload)
	if err != nil {
		if errors.Is(err, iam.ErrRoleBindingNotFound) {
			http.Error(w, "Role binding not found: "+bindingID, http.StatusNotFound)
		} else {
			// This could also include errors if the service layer rejected an attempted change to immutable fields.
			log.Printf("Admin: UpdateRoleBinding error for ID '%s': %v", bindingID, err)
			http.Error(w, "Failed to update role binding: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: 'Updated' RoleBinding (no-op for current structure): ID=%s", updatedBinding.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedBinding)
}

// --- IAM: ServiceAccount Handlers ---

// CreateServiceAccountRequest defines the payload for creating a new service account.
type CreateServiceAccountRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"` // e.g., "active", "disabled". Defaults to "active" if empty.
}

// CreateServiceAccount handles POST /admin/iam/serviceaccounts
func (h *Handler) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	var req CreateServiceAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Service account name is required", http.StatusBadRequest)
		return
	}

	saToCreate := &iam.ServiceAccount{
		Name:        req.Name,
		Description: req.Description,
		Status:      req.Status, // Service will default to "active" if empty
	}

	createdSA, err := h.iamService.CreateServiceAccount(r.Context(), saToCreate)
	if err != nil {
		if errors.Is(err, iam.ErrServiceAccountAlreadyExists) {
			http.Error(w, "Service account with this name already exists: "+err.Error(), http.StatusConflict)
		} else {
			log.Printf("Admin: CreateServiceAccount error: %v", err)
			http.Error(w, "Failed to create service account: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Created ServiceAccount: Name=%s, ID=%s", createdSA.Name, createdSA.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdSA)
}

// ListServiceAccounts handles GET /admin/iam/serviceaccounts
func (h *Handler) ListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	limit, offset := getPaginationParams(queryParams)
	nameFilter := queryParams.Get("name_filter")
	statusFilter := queryParams.Get("status_filter")

	listOpts := iam.ListServiceAccountOptions{
		Limit:        limit,
		Offset:       offset,
		NameFilter:   nameFilter,
		StatusFilter: statusFilter,
	}

	serviceAccounts, totalCount, err := h.iamService.ListServiceAccounts(r.Context(), listOpts)
	if err != nil {
		log.Printf("Admin: ListServiceAccounts error: %v", err)
		http.Error(w, "Failed to list service accounts: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := struct {
		ServiceAccounts []*iam.ServiceAccount `json:"service_accounts"`
		TotalCount      int                   `json:"total_count"`
		Offset          int                   `json:"offset"`
		Limit           int                   `json:"limit"`
	}{
		ServiceAccounts: serviceAccounts, // This is already paginated by the service
		TotalCount:      totalCount,
		Offset:          offset,
		Limit:           limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetServiceAccount handles GET /admin/iam/serviceaccounts/{serviceAccountID}
func (h *Handler) GetServiceAccount(w http.ResponseWriter, r *http.Request) {
	saID := chi.URLParam(r, "serviceAccountID")
	if saID == "" {
		http.Error(w, "Service Account ID parameter is required", http.StatusBadRequest)
		return
	}

	serviceAccount, err := h.iamService.GetServiceAccount(r.Context(), saID)
	if err != nil {
		if errors.Is(err, iam.ErrServiceAccountNotFound) {
			http.Error(w, "Service account not found: "+saID, http.StatusNotFound)
		} else {
			log.Printf("Admin: GetServiceAccount error for ID '%s': %v", saID, err)
			http.Error(w, "Failed to get service account: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(serviceAccount)
}

// UpdateServiceAccountRequest defines the payload for updating a service account.
type UpdateServiceAccountRequest struct {
	Name        *string `json:"name,omitempty"`        // Pointer to distinguish between empty and not provided
	Description *string `json:"description,omitempty"` // Pointer to allow clearing description
	Status      *string `json:"status,omitempty"`      // e.g., "active", "disabled"
}

// UpdateServiceAccount handles PATCH /admin/iam/serviceaccounts/{serviceAccountID}
func (h *Handler) UpdateServiceAccount(w http.ResponseWriter, r *http.Request) {
	saID := chi.URLParam(r, "serviceAccountID")
	if saID == "" {
		http.Error(w, "Service Account ID parameter is required", http.StatusBadRequest)
		return
	}

	var req UpdateServiceAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	saUpdatePayload := &iam.ServiceAccount{} // Fields will be set if provided in req

	if req.Name != nil {
		if *req.Name == "" {
			http.Error(w, "Service account name cannot be empty if provided for update", http.StatusBadRequest)
			return
		}
		saUpdatePayload.Name = *req.Name
	}
	if req.Description != nil {
		saUpdatePayload.Description = *req.Description
	}
	if req.Status != nil {
		if *req.Status != "active" && *req.Status != "disabled" && *req.Status != "" { // Allow empty to not update
			http.Error(w, "Invalid status, must be 'active' or 'disabled'", http.StatusBadRequest)
			return
		}
		saUpdatePayload.Status = *req.Status
	}

	updatedSA, err := h.iamService.UpdateServiceAccount(r.Context(), saID, saUpdatePayload)
	if err != nil {
		if errors.Is(err, iam.ErrServiceAccountNotFound) {
			http.Error(w, "Service account not found: "+saID, http.StatusNotFound)
		} else if errors.Is(err, iam.ErrServiceAccountAlreadyExists) {
			http.Error(w, "Service account name conflict: "+err.Error(), http.StatusConflict)
		} else {
			log.Printf("Admin: UpdateServiceAccount error for ID '%s': %v", saID, err)
			http.Error(w, "Failed to update service account: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Updated ServiceAccount: ID=%s", updatedSA.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedSA)
}

// DeleteServiceAccount handles DELETE /admin/iam/serviceaccounts/{serviceAccountID}
func (h *Handler) DeleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	saID := chi.URLParam(r, "serviceAccountID")
	if saID == "" {
		http.Error(w, "Service Account ID parameter is required", http.StatusBadRequest)
		return
	}

	// Remove role bindings associated with this service account before deleting it.
	// Using "serviceaccount" as principalType string.
	if err := h.iamService.RemoveRoleBindingsForPrincipal(r.Context(), saID, "serviceaccount"); err != nil {
		// Log the error but proceed with service account deletion attempt.
		// Depending on policy, this could be a hard failure.
		log.Printf("Admin: DeleteServiceAccount - Failed to remove role bindings for SA ID '%s': %v. Proceeding with SA deletion.", saID, err)
	}

	// Delete API keys associated with this service account.
	// This requires h.iamService to have a DeleteAPIKeysForPrincipal method.
	/*
		if err := h.iamService.DeleteAPIKeysForPrincipal(r.Context(), saID, "serviceaccount"); err != nil {
			// Log the error but proceed with service account deletion attempt.
			log.Printf("Admin: DeleteServiceAccount - Failed to delete API keys for SA ID '%s': %v. Proceeding with SA deletion.", saID, err)
		}
	*/

	err := h.iamService.DeleteServiceAccount(r.Context(), saID)
	if err != nil {
		if errors.Is(err, iam.ErrServiceAccountNotFound) {
			http.Error(w, "Service account not found: "+saID, http.StatusNotFound)
		} else {
			log.Printf("Admin: DeleteServiceAccount error for ID '%s': %v", saID, err)
			http.Error(w, "Failed to delete service account: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Deleted ServiceAccount: ID=%s", saID)
	w.WriteHeader(http.StatusNoContent)
}

// --- IAM: User Handlers ---

// CreateUserRequest defines the payload for creating a new user.
type CreateUserRequest struct {
	Email     string   `json:"email"`
	Status    string   `json:"status,omitempty"`     // e.g., "active", "disabled". Defaults to "active".
	RoleNames []string `json:"role_names,omitempty"` // Optional direct roles for the user
}

// CreateUser handles POST /admin/iam/users
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		http.Error(w, "User email is required", http.StatusBadRequest)
		return
	}

	// Validate email format
	if _, err := mail.ParseAddress(req.Email); err != nil {
		http.Error(w, "Invalid email format: "+err.Error(), http.StatusBadRequest)
		return
	}

	userToCreate := &iam.User{
		Email:     req.Email,
		Status:    req.Status, // Service will default to "active" if empty
		RoleNames: req.RoleNames,
	}

	createdUser, err := h.iamService.CreateUser(r.Context(), userToCreate)
	if err != nil {
		if errors.Is(err, iam.ErrUserAlreadyExists) {
			http.Error(w, "User with this email already exists: "+err.Error(), http.StatusConflict)
		} else {
			log.Printf("Admin: CreateUser error: %v", err)
			http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Created User: Email=%s, ID=%s", createdUser.Email, createdUser.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdUser)
}

// ListUsers handles GET /admin/iam/users
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	limit, offset := getPaginationParams(queryParams)
	statusFilter := queryParams.Get("status_filter")
	emailContainsFilter := queryParams.Get("email_contains_filter")

	listOpts := iam.ListUserOptions{
		Limit:               limit,
		Offset:              offset,
		StatusFilter:        statusFilter,
		EmailContainsFilter: emailContainsFilter,
	}

	users, totalCount, err := h.iamService.ListUsers(r.Context(), listOpts)
	if err != nil {
		log.Printf("Admin: ListUsers error: %v", err)
		http.Error(w, "Failed to list users: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The iam.User struct is simple (ID, Email, Status, CreatedAt, UpdatedAt).
	// If more detailed info (like DisplayName, GroupIDs from config.UserConfig) is needed here,
	// this handler would need to fetch that additional info and combine it.
	// For now, returning the basic iam.User data.
	response := struct {
		Users      []*iam.User `json:"users"`
		TotalCount int         `json:"total_count"`
		Offset     int         `json:"offset"`
		Limit      int         `json:"limit"`
	}{
		Users:      users, // This is already paginated by the service
		TotalCount: totalCount,
		Offset:     offset,
		Limit:      limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetUser handles GET /admin/iam/users/{userID}
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		http.Error(w, "User ID parameter is required", http.StatusBadRequest)
		return
	}

	user, err := h.iamService.GetUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, iam.ErrUserNotFound) {
			http.Error(w, "User not found: "+userID, http.StatusNotFound)
		} else {
			log.Printf("Admin: GetUser error for ID '%s': %v", userID, err)
			http.Error(w, "Failed to get user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// The iam.User struct is basic. If DisplayName, GroupIDs etc. are needed from
	// config.UserConfig, this handler would need to fetch and combine that data.
	// For now, returning the iam.User.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// UpdateUserRequest defines the payload for updating an existing user.
// Email is not updatable. Status and RoleNames are supported for update.
type UpdateUserRequest struct {
	Status    *string   `json:"status,omitempty"`     // Pointer to distinguish between empty and not provided
	RoleNames *[]string `json:"role_names,omitempty"` // Pointer to allow clearing or setting roles
}

// UpdateUser handles PATCH /admin/iam/users/{userID}
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		http.Error(w, "User ID parameter is required", http.StatusBadRequest)
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	userUpdatePayload := &iam.User{} // Fields will be set if provided in req

	if req.Status != nil {
		if *req.Status != "active" && *req.Status != "disabled" && *req.Status != "" { // Allow empty string to not update
			http.Error(w, "Invalid status, must be 'active' or 'disabled'", http.StatusBadRequest)
			return
		}
		userUpdatePayload.Status = *req.Status
	}

	if req.RoleNames != nil {
		// iamService.UpdateUser will validate these role names
		userUpdatePayload.RoleNames = *req.RoleNames
	}
	// Note: Email is not updatable through this endpoint.

	updatedUser, err := h.iamService.UpdateUser(r.Context(), userID, userUpdatePayload)
	if err != nil {
		if errors.Is(err, iam.ErrUserNotFound) {
			http.Error(w, "User not found: "+userID, http.StatusNotFound)
		} else {
			log.Printf("Admin: UpdateUser error for ID '%s': %v", userID, err)
			http.Error(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Updated User: ID=%s", updatedUser.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedUser)
}

// DeleteUser handles DELETE /admin/iam/users/{userID}
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		http.Error(w, "User ID parameter is required", http.StatusBadRequest)
		return
	}

	// TODO: Consider implications for API keys, role bindings, group memberships
	// associated with this user. For now, it's a direct delete of the user entity.

	err := h.iamService.DeleteUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, iam.ErrUserNotFound) {
			http.Error(w, "User not found: "+userID, http.StatusNotFound)
		} else {
			log.Printf("Admin: DeleteUser error for ID '%s': %v", userID, err)
			http.Error(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Deleted User: ID=%s", userID)
	w.WriteHeader(http.StatusNoContent)
}

// --- IAM: User API Key Handlers ---

// CreateUserAPIKeyRequest defines the payload for creating a new API key for a user.
type CreateUserAPIKeyRequest struct {
	Name      string   `json:"name,omitempty"`       // Optional name for the key
	RoleNames []string `json:"role_names,omitempty"` // Optional roles to associate with the key
	ExpiresAt string   `json:"expires_at,omitempty"` // Optional expiration date in RFC3339 format (e.g., "2023-12-31T23:59:59Z")
}

// CreateUserAPIKeyResponse defines the response payload, including the raw API key.
type CreateUserAPIKeyResponse struct {
	RawAPIKey string      `json:"raw_api_key"`      // The actual API key, show only on creation
	APIKey    *iam.APIKey `json:"api_key_metadata"` // Metadata of the created key (excluding raw key)
}

// CreateUserAPIKey handles POST /admin/iam/users/{userID}/apikeys
func (h *Handler) CreateUserAPIKey(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		http.Error(w, "User ID parameter is required", http.StatusBadRequest)
		return
	}

	// First, check if the user exists
	_, err := h.iamService.GetUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, iam.ErrUserNotFound) {
			http.Error(w, "User not found: "+userID, http.StatusNotFound)
		} else {
			log.Printf("Admin: CreateUserAPIKey - Error checking user ID '%s': %v", userID, err)
			http.Error(w, "Failed to validate user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	var req CreateUserAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var expiresAtTime time.Time
	if req.ExpiresAt != "" {
		parsedTime, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			http.Error(w, "Invalid expires_at format, use RFC3339 (e.g., YYYY-MM-DDTHH:MM:SSZ): "+err.Error(), http.StatusBadRequest)
			return
		}
		expiresAtTime = parsedTime
	}

	// TODO: Validate RoleNames if provided (check if roles exist)

	rawKey, apiKeyMeta, err := h.iamService.GenerateAPIKey(r.Context(), userID, req.Name, req.RoleNames, expiresAtTime)
	if err != nil {
		// This could be due to various reasons, e.g., failure to write to store.
		log.Printf("Admin: CreateUserAPIKey - Error generating API key for user '%s': %v", userID, err)
		http.Error(w, "Failed to generate API key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Important: Do not include HashedKey in the response for security.
	// The APIKey struct from iamService.GenerateAPIKey already has HashedKey.
	// We create a new struct or nil out HashedKey for the response.
	responseKeyMeta := &iam.APIKey{
		ID:         apiKeyMeta.ID,
		UserID:     apiKeyMeta.UserID,
		Name:       apiKeyMeta.Name,
		RoleNames:  apiKeyMeta.RoleNames,
		ExpiresAt:  apiKeyMeta.ExpiresAt,
		LastUsedAt: apiKeyMeta.LastUsedAt,
		CreatedAt:  apiKeyMeta.CreatedAt,
		Revoked:    apiKeyMeta.Revoked,
	}

	response := CreateUserAPIKeyResponse{
		RawAPIKey: rawKey,
		APIKey:    responseKeyMeta,
	}

	log.Printf("Admin: Created API Key ID %s for User ID %s", apiKeyMeta.ID, userID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// ListUserAPIKeys handles GET /admin/iam/users/{userID}/apikeys
func (h *Handler) ListUserAPIKeys(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		http.Error(w, "User ID parameter is required", http.StatusBadRequest)
		return
	}

	// Service method ListUserAPIKeys already checks if user exists.
	apiKeyMetas, err := h.iamService.ListUserAPIKeys(r.Context(), userID)
	if err != nil {
		if errors.Is(err, iam.ErrUserNotFound) { // Should be handled by service, but good to check
			http.Error(w, "User not found: "+userID, http.StatusNotFound)
		} else {
			log.Printf("Admin: ListUserAPIKeys error for User ID '%s': %v", userID, err)
			http.Error(w, "Failed to list API keys: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Sanitize API keys for response (remove HashedKey)
	sanitizedKeys := make([]*iam.APIKey, 0, len(apiKeyMetas))
	for _, keyMeta := range apiKeyMetas {
		sanitizedKeys = append(sanitizedKeys, &iam.APIKey{
			ID:         keyMeta.ID,
			UserID:     keyMeta.UserID,
			Name:       keyMeta.Name,
			RoleNames:  keyMeta.RoleNames,
			ExpiresAt:  keyMeta.ExpiresAt,
			LastUsedAt: keyMeta.LastUsedAt,
			CreatedAt:  keyMeta.CreatedAt,
			Revoked:    keyMeta.Revoked,
		})
	}

	response := struct {
		APIKeys []*iam.APIKey `json:"api_keys"`
		Count   int           `json:"count"`
	}{
		APIKeys: sanitizedKeys,
		Count:   len(sanitizedKeys),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DeleteAPIKey handles DELETE /admin/iam/apikeys/{apiKeyID}
// This is a general endpoint to delete any API key by its ID.
func (h *Handler) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	apiKeyID := chi.URLParam(r, "apiKeyID")
	if apiKeyID == "" {
		http.Error(w, "API Key ID parameter is required", http.StatusBadRequest)
		return
	}

	err := h.iamService.DeleteAPIKey(r.Context(), apiKeyID)
	if err != nil {
		if errors.Is(err, iam.ErrAPIKeyNotFound) {
			http.Error(w, "API Key not found: "+apiKeyID, http.StatusNotFound)
		} else {
			log.Printf("Admin: DeleteAPIKey error for ID '%s': %v", apiKeyID, err)
			http.Error(w, "Failed to delete API key: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Deleted API Key: ID=%s", apiKeyID)
	w.WriteHeader(http.StatusNoContent)
}

// --- Route Handlers (Placeholders) ---

// CreateRoute handles POST /admin/routes
func (h *Handler) CreateRoute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var newRouteReq config.RouteConfig
	if err := json.NewDecoder(r.Body).Decode(&newRouteReq); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Basic validation
	if newRouteReq.Name == "" {
		http.Error(w, "Route name is required", http.StatusBadRequest)
		return
	}
	if newRouteReq.Protocol == "" {
		http.Error(w, "Route protocol is required", http.StatusBadRequest)
		return
	}
	if len(newRouteReq.Targets) == 0 {
		http.Error(w, "Route must have at least one target", http.StatusBadRequest)
		return
	}

	// Validate RouteConfig.Match
	if newRouteReq.Match.PathPrefix != "" && !strings.HasPrefix(newRouteReq.Match.PathPrefix, "/") {
		http.Error(w, "Invalid route match: PathPrefix must start with '/'", http.StatusBadRequest)
		return
	}
	// Basic check: ensure at least one match criteria is usually present if not a catch-all
	// More complex validation (e.g., only one of ModelID, ToolID, AgentID) could be added.

	// Validate RouteConfig.Targets
	for i, target := range newRouteReq.Targets {
		if target.Ref == "" {
			http.Error(w, fmt.Sprintf("Invalid route target at index %d: Ref (ModelID, ToolID, or AgentID) is required", i), http.StatusBadRequest)
			return
		}
		if target.Weight < 0 {
			http.Error(w, fmt.Sprintf("Invalid route target at index %d: Weight must be non-negative", i), http.StatusBadRequest)
			return
		}
		// Further validation: check if Ref exists (e.g., h.modelService.GetModel(target.Ref))
		// This might be too slow for a simple create handler or better handled by a routing validation service.
	}

	// Validate RouteConfig.Policy
	if newRouteReq.Policy.Strategy != "" {
		validStrategies := map[string]bool{"round_robin": true, "least_busy": true, "weighted_random": true, "failover": true} // Add more as they are implemented
		if !validStrategies[newRouteReq.Policy.Strategy] {
			http.Error(w, fmt.Sprintf("Invalid route policy strategy: '%s'", newRouteReq.Policy.Strategy), http.StatusBadRequest)
			return
		}
	}
	if newRouteReq.Policy.RetryAttempts < 0 {
		http.Error(w, "Invalid route policy: RetryAttempts must be non-negative", http.StatusBadRequest)
		return
	}
	if newRouteReq.Policy.TimeoutMs < 0 { // 0 might mean no timeout or use global default
		http.Error(w, "Invalid route policy: TimeoutMs must be non-negative", http.StatusBadRequest)
		return
	}
	if cb := newRouteReq.Policy.CircuitBreaker; cb != nil {
		if cb.ConsecutiveErrors <= 0 {
			http.Error(w, "Invalid circuit breaker: ConsecutiveErrors must be positive", http.StatusBadRequest)
			return
		}
		if cb.IntervalMs <= 0 {
			http.Error(w, "Invalid circuit breaker: IntervalMs must be positive", http.StatusBadRequest)
			return
		}
		if cb.TimeoutMs <= 0 {
			http.Error(w, "Invalid circuit breaker: TimeoutMs (for breaker open state) must be positive", http.StatusBadRequest)
			return
		}
	}

	if newRouteReq.ID == "" {
		newRouteReq.ID = uuid.NewString()
	}
	newRouteReq.CreatedAt = time.Now().UTC()
	newRouteReq.UpdatedAt = time.Now().UTC()

	// Store the individual route config
	routeStoreKey := "routes/" + newRouteReq.ID
	routeData, err := json.Marshal(newRouteReq)
	if err != nil {
		log.Printf("Admin: CreateRoute - Failed to marshal route data: %v", err)
		http.Error(w, "Failed to process route data", http.StatusInternalServerError)
		return
	}
	if err := h.store.Set(ctx, routeStoreKey, routeData); err != nil {
		log.Printf("Admin: CreateRoute - Failed to save route to store: %v", err)
		http.Error(w, "Failed to save route", http.StatusInternalServerError)
		return
	}

	// Update the full RuntimeConfig
	if err := h.updateRuntimeConfigWithRoute(ctx, newRouteReq, false); err != nil {
		// Log the error, but the individual route was saved.
		// Depending on desired atomicity, might consider rolling back the individual save.
		log.Printf("Admin: CreateRoute - Failed to update full RuntimeConfig after creating route %s: %v", newRouteReq.ID, err)
		// Potentially return a warning or a different status if RuntimeConfig update fails.
	}

	log.Printf("Admin: Created Route: ID=%s, Name=%s", newRouteReq.ID, newRouteReq.Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newRouteReq)
}

// updateRuntimeConfigWithRoute adds, updates, or removes a route from the full RuntimeConfig
// and saves it to the store. If isDelete is true, the route is removed. Otherwise, it's added/updated.
func (h *Handler) updateRuntimeConfigWithRoute(ctx context.Context, routeCfg config.RouteConfig, isDelete bool) error {
	fullRuntimeConfig := h.configMgr.GetCurrentConfig()
	if fullRuntimeConfig == nil {
		return fmt.Errorf("current full runtime configuration not available from ConfigManager")
	}

	found := false
	updatedRoutes := []config.RouteConfig{}
	for _, existingRoute := range fullRuntimeConfig.Routes {
		if existingRoute.ID == routeCfg.ID {
			found = true
			if !isDelete { // Update existing
				updatedRoutes = append(updatedRoutes, routeCfg)
			}
			// If isDelete, we skip appending, effectively removing it
		} else {
			updatedRoutes = append(updatedRoutes, existingRoute)
		}
	}

	if !found && !isDelete { // Add new route
		updatedRoutes = append(updatedRoutes, routeCfg)
	}

	fullRuntimeConfig.Routes = updatedRoutes
	fullRuntimeConfig.LastUpdated = time.Now().UTC()

	runtimeConfigData, marshalErr := json.Marshal(fullRuntimeConfig)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal full RuntimeConfig for update: %w", marshalErr)
	}

	const runtimeConfigKey = "config/runtime/current"
	if errStoreRuntime := h.store.Set(ctx, runtimeConfigKey, runtimeConfigData); errStoreRuntime != nil {
		return fmt.Errorf("failed to store updated RuntimeConfig to '%s': %w", runtimeConfigKey, errStoreRuntime)
	}
	log.Printf("Admin: Updated RuntimeConfig in store ('%s') due to route change for ID %s.", runtimeConfigKey, routeCfg.ID)
	return nil
}

// ListRoutes handles GET /admin/routes
func (h *Handler) ListRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queryParams := r.URL.Query()
	limit, offset := getPaginationParams(queryParams)
	nameFilter := queryParams.Get("name_filter")         // Filter by name (contains, case-insensitive)
	protocolFilter := queryParams.Get("protocol_filter") // Filter by protocol (exact match)
	sortBy := queryParams.Get("sort_by")                 // e.g., "name_asc", "priority_desc", "created_at_asc"

	allRouteData, err := h.store.List(ctx, "routes/")
	if err != nil {
		log.Printf("Admin: ListRoutes - Failed to list routes from store: %v", err)
		http.Error(w, "Failed to list routes", http.StatusInternalServerError)
		return
	}

	allRoutesFromStore := make([]config.RouteConfig, 0, len(allRouteData))
	for _, data := range allRouteData {
		var routeCfg config.RouteConfig
		if err := json.Unmarshal(data, &routeCfg); err == nil {
			allRoutesFromStore = append(allRoutesFromStore, routeCfg)
		} else {
			log.Printf("Admin: ListRoutes - Failed to unmarshal route data: %v", err)
		}
	}

	// Apply filters
	filteredRoutes := make([]config.RouteConfig, 0, len(allRoutesFromStore))
	for _, route := range allRoutesFromStore {
		matches := true
		if nameFilter != "" {
			if !strings.Contains(strings.ToLower(route.Name), strings.ToLower(nameFilter)) {
				matches = false
			}
		}
		if matches && protocolFilter != "" {
			if string(route.Protocol) != protocolFilter {
				matches = false
			}
		}
		if matches {
			filteredRoutes = append(filteredRoutes, route)
		}
	}

	// TODO: Sort routes if necessary (e.g., by name, priority, or created_at)
	// Apply sorting
	switch sortBy {
	case "name_asc":
		sort.SliceStable(filteredRoutes, func(i, j int) bool { return filteredRoutes[i].Name < filteredRoutes[j].Name })
	case "name_desc":
		sort.SliceStable(filteredRoutes, func(i, j int) bool { return filteredRoutes[i].Name > filteredRoutes[j].Name })
	case "priority_asc":
		sort.SliceStable(filteredRoutes, func(i, j int) bool { return filteredRoutes[i].Priority < filteredRoutes[j].Priority })
	case "priority_desc":
		sort.SliceStable(filteredRoutes, func(i, j int) bool { return filteredRoutes[i].Priority > filteredRoutes[j].Priority })
	case "created_at_asc":
		sort.SliceStable(filteredRoutes, func(i, j int) bool { return filteredRoutes[i].CreatedAt.Before(filteredRoutes[j].CreatedAt) })
	case "created_at_desc":
		sort.SliceStable(filteredRoutes, func(i, j int) bool { return filteredRoutes[i].CreatedAt.After(filteredRoutes[j].CreatedAt) })
	default: // Default sort by ID for consistent pagination if no valid sort_by is provided
		sort.SliceStable(filteredRoutes, func(i, j int) bool {
			return filteredRoutes[i].ID < filteredRoutes[j].ID
		})
	}

	totalCount := len(filteredRoutes)
	paginatedRoutes := paginate(filteredRoutes, offset, limit)

	response := struct {
		Routes     []config.RouteConfig `json:"routes"`
		TotalCount int                  `json:"total_count"`
		Offset     int                  `json:"offset"`
		Limit      int                  `json:"limit"`
	}{
		Routes:     paginatedRoutes,
		TotalCount: totalCount,
		Offset:     offset,
		Limit:      limit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetRoute handles GET /admin/routes/{routeID}
func (h *Handler) GetRoute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	routeID := chi.URLParam(r, "routeID")
	if routeID == "" {
		http.Error(w, "Route ID parameter is required", http.StatusBadRequest)
		return
	}

	routeStoreKey := "routes/" + routeID
	routeData, err := h.store.Get(ctx, routeStoreKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Route not found: "+routeID, http.StatusNotFound)
		} else {
			log.Printf("Admin: GetRoute - Failed to get route %s from store: %v", routeID, err)
			http.Error(w, "Failed to get route", http.StatusInternalServerError)
		}
		return
	}

	var routeCfg config.RouteConfig
	if err := json.Unmarshal(routeData, &routeCfg); err != nil {
		log.Printf("Admin: GetRoute - Failed to unmarshal route data for %s: %v", routeID, err)
		http.Error(w, "Failed to process route data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routeCfg)
}

// UpdateRoute handles PATCH /admin/routes/{routeID}
func (h *Handler) UpdateRoute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	routeID := chi.URLParam(r, "routeID")
	if routeID == "" {
		http.Error(w, "Route ID parameter is required", http.StatusBadRequest)
		return
	}

	routeStoreKey := "routes/" + routeID
	existingRouteData, err := h.store.Get(ctx, routeStoreKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Route not found: "+routeID, http.StatusNotFound)
		} else {
			log.Printf("Admin: UpdateRoute - Failed to get route %s from store: %v", routeID, err)
			http.Error(w, "Failed to get route for update", http.StatusInternalServerError)
		}
		return
	}

	var existingRouteCfg config.RouteConfig
	if err := json.Unmarshal(existingRouteData, &existingRouteCfg); err != nil {
		log.Printf("Admin: UpdateRoute - Failed to unmarshal existing route data for %s: %v", routeID, err)
		http.Error(w, "Failed to process existing route data", http.StatusInternalServerError)
		return
	}

	var updateReq config.RouteConfig
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Apply updates - ID and CreatedAt should not change.
	updatedRouteCfg := existingRouteCfg
	if updateReq.Name != "" {
		updatedRouteCfg.Name = updateReq.Name
	}
	if updateReq.Protocol != "" {
		updatedRouteCfg.Protocol = updateReq.Protocol
	}
	if updateReq.Priority != 0 { // Assuming 0 is not a valid user-set priority, or use a pointer
		updatedRouteCfg.Priority = updateReq.Priority
	}
	if len(updateReq.Targets) > 0 { // Replace targets if provided
		updatedRouteCfg.Targets = updateReq.Targets
	}
	// For Match and Policy, a full replacement is simpler for PATCH here.
	// More granular updates would require more complex logic or a different PATCH strategy (e.g., JSON Merge Patch).
	// Check if any field in Match is set, indicating an update.
	if updateReq.Match.PathPrefix != "" || updateReq.Match.ModelID != "" || updateReq.Match.ToolID != "" || updateReq.Match.AgentID != "" || updateReq.Match.TaskName != "" || len(updateReq.Match.Headers) > 0 {
		updatedRouteCfg.Match = updateReq.Match
	}
	// Check if Policy is set (any field non-default).
	if updateReq.Policy.Strategy != "" || updateReq.Policy.RetryOnFailure || updateReq.Policy.RetryAttempts != 0 || updateReq.Policy.TimeoutMs != 0 || updateReq.Policy.CircuitBreaker != nil {
		updatedRouteCfg.Policy = updateReq.Policy
	}
	// Check if Plugins are set (Pre or Post has entries or is explicitly empty).
	if updateReq.Plugins.Pre != nil || updateReq.Plugins.Post != nil {
		updatedRouteCfg.Plugins = updateReq.Plugins
	}
	// AllowedPrincipals: if nil in request, don't change. If empty array, clear. If populated, set.
	if updateReq.AllowedPrincipals != nil {
		updatedRouteCfg.AllowedPrincipals = updateReq.AllowedPrincipals
	}
	updatedRouteCfg.UpdatedAt = time.Now().UTC()

	// Validate updatedRouteCfg (similar to CreateRoute validation)
	// Validate RouteConfig.Match
	if updatedRouteCfg.Match.PathPrefix != "" && !strings.HasPrefix(updatedRouteCfg.Match.PathPrefix, "/") {
		http.Error(w, "Invalid route match: PathPrefix must start with '/'", http.StatusBadRequest)
		return
	}

	// Validate RouteConfig.Targets
	if len(updatedRouteCfg.Targets) == 0 { // Ensure targets are not cleared to an empty state if they were required
		http.Error(w, "Route must have at least one target", http.StatusBadRequest)
		return
	}
	for i, target := range updatedRouteCfg.Targets {
		if target.Ref == "" {
			http.Error(w, fmt.Sprintf("Invalid route target at index %d: Ref (ModelID, ToolID, or AgentID) is required", i), http.StatusBadRequest)
			return
		}
		if target.Weight < 0 {
			http.Error(w, fmt.Sprintf("Invalid route target at index %d: Weight must be non-negative", i), http.StatusBadRequest)
			return
		}
	}

	// Validate RouteConfig.Policy
	if updatedRouteCfg.Policy.Strategy != "" {
		validStrategies := map[string]bool{"round_robin": true, "least_busy": true, "weighted_random": true, "failover": true}
		if !validStrategies[updatedRouteCfg.Policy.Strategy] {
			http.Error(w, fmt.Sprintf("Invalid route policy strategy: '%s'", updatedRouteCfg.Policy.Strategy), http.StatusBadRequest)
			return
		}
	}
	if updatedRouteCfg.Policy.RetryAttempts < 0 {
		http.Error(w, "Invalid route policy: RetryAttempts must be non-negative", http.StatusBadRequest)
		return
	}
	if updatedRouteCfg.Policy.TimeoutMs < 0 {
		http.Error(w, "Invalid route policy: TimeoutMs must be non-negative", http.StatusBadRequest)
		return
	}
	if cb := updatedRouteCfg.Policy.CircuitBreaker; cb != nil {
		if cb.ConsecutiveErrors <= 0 {
			http.Error(w, "Invalid circuit breaker: ConsecutiveErrors must be positive", http.StatusBadRequest)
			return
		}
		if cb.IntervalMs <= 0 {
			http.Error(w, "Invalid circuit breaker: IntervalMs must be positive", http.StatusBadRequest)
			return
		}
		if cb.TimeoutMs <= 0 {
			http.Error(w, "Invalid circuit breaker: TimeoutMs (for breaker open state) must be positive", http.StatusBadRequest)
			return
		}
	}

	// Store the updated individual route config
	updatedRouteData, err := json.Marshal(updatedRouteCfg)
	if err != nil {
		log.Printf("Admin: UpdateRoute - Failed to marshal updated route data for %s: %v", routeID, err)
		http.Error(w, "Failed to process updated route data", http.StatusInternalServerError)
		return
	}
	if err := h.store.Set(ctx, routeStoreKey, updatedRouteData); err != nil {
		log.Printf("Admin: UpdateRoute - Failed to save updated route %s to store: %v", routeID, err)
		http.Error(w, "Failed to save updated route", http.StatusInternalServerError)
		return
	}

	// Update the full RuntimeConfig
	if err := h.updateRuntimeConfigWithRoute(ctx, updatedRouteCfg, false); err != nil {
		log.Printf("Admin: UpdateRoute - Failed to update full RuntimeConfig after updating route %s: %v", routeID, err)
		// Consider consistency implications
	}

	log.Printf("Admin: Updated Route: ID=%s, Name=%s", updatedRouteCfg.ID, updatedRouteCfg.Name)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedRouteCfg)
}

// DeleteRoute handles DELETE /admin/routes/{routeID}
func (h *Handler) DeleteRoute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	routeID := chi.URLParam(r, "routeID")
	if routeID == "" {
		http.Error(w, "Route ID parameter is required", http.StatusBadRequest)
		return
	}

	routeStoreKey := "routes/" + routeID

	// Check if route exists before trying to delete
	_, err := h.store.Get(ctx, routeStoreKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Route not found: "+routeID, http.StatusNotFound)
		} else {
			log.Printf("Admin: DeleteRoute - Error checking route %s from store: %v", routeID, err)
			http.Error(w, "Failed to get route for deletion", http.StatusInternalServerError)
		}
		return
	}

	if err := h.store.Delete(ctx, routeStoreKey); err != nil {
		log.Printf("Admin: DeleteRoute - Failed to delete route %s from store: %v", routeID, err)
		http.Error(w, "Failed to delete route", http.StatusInternalServerError)
		return
	}

	// Update the full RuntimeConfig by removing the route
	// Pass an empty RouteConfig with only the ID set, and isDelete = true
	if err := h.updateRuntimeConfigWithRoute(ctx, config.RouteConfig{ID: routeID}, true); err != nil {
		log.Printf("Admin: DeleteRoute - Failed to update full RuntimeConfig after deleting route %s: %v", routeID, err)
		// Consider consistency implications. The individual route is deleted, but RuntimeConfig update failed.
	}

	log.Printf("Admin: Deleted Route: ID=%s", routeID)
	w.WriteHeader(http.StatusNoContent)
}

// DeleteModel handles DELETE /admin/models/{modelID}
func (h *Handler) DeleteModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modelID := chi.URLParam(r, "modelID")
	if modelID == "" {
		http.Error(w, "Model ID parameter is required", http.StatusBadRequest)
		return
	}

	modelStoreKey := "models/" + modelID

	// Check if model exists
	_, err := h.store.Get(ctx, modelStoreKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Model not found: "+modelID, http.StatusNotFound)
		} else {
			log.Printf("Admin: DeleteModel - Error checking model %s from store: %v", modelID, err)
			http.Error(w, "Failed to get model for deletion", http.StatusInternalServerError)
		}
		return
	}

	// Dependency Check: Check if model is used in any routes
	force := r.URL.Query().Get("force") == "true"
	if !force {
		fullRuntimeConfig := h.configMgr.GetCurrentConfig()
		if fullRuntimeConfig != nil {
			for _, route := range fullRuntimeConfig.Routes {
				if route.Protocol == config.ProtocolHTTPLLM { // Only LLM routes directly reference ModelConfig by ID in targets
					for _, target := range route.Targets {
						if target.Ref == modelID {
							http.Error(w, fmt.Sprintf("Cannot delete model ID '%s': used by route '%s' (target ref). Use force=true to override.", modelID, route.ID), http.StatusConflict)
							return
						}
					}
				}
				// Also check Match.ModelID
				if route.Match.ModelID == modelID {
					http.Error(w, fmt.Sprintf("Cannot delete model ID '%s': used by route '%s' (match criteria). Use force=true to override.", modelID, route.ID), http.StatusConflict)
					return
				}
			}
		}
	}

	// Delete the individual model config
	if err := h.store.Delete(ctx, modelStoreKey); err != nil {
		log.Printf("Admin: DeleteModel - Failed to delete model %s from store: %v", modelID, err)
		http.Error(w, "Failed to delete model", http.StatusInternalServerError)
		return
	}

	// Update the full RuntimeConfig by removing the model
	if err := h.updateRuntimeConfigWithModel(ctx, config.ModelConfig{ID: modelID}, true); err != nil {
		log.Printf("Admin: DeleteModel - Failed to update full RuntimeConfig after deleting model %s: %v", modelID, err)
		// Consider consistency implications
	}

	log.Printf("Admin: Deleted Model: ID=%s", modelID)
	w.WriteHeader(http.StatusNoContent)
}

// updateRuntimeConfigWithModel adds, updates, or removes a model from the full RuntimeConfig
// and saves it to the store. If isDelete is true, the model is removed. Otherwise, it's added/updated.
// This helper is analogous to updateRuntimeConfigWithRoute.
func (h *Handler) updateRuntimeConfigWithModel(ctx context.Context, modelCfg config.ModelConfig, isDelete bool) error {
	fullRuntimeConfig := h.configMgr.GetCurrentConfig()
	if fullRuntimeConfig == nil {
		return fmt.Errorf("current full runtime configuration not available from ConfigManager")
	}

	found := false
	updatedModels := []config.ModelConfig{}
	for _, existingModel := range fullRuntimeConfig.Models {
		if existingModel.ID == modelCfg.ID {
			found = true
			if !isDelete { // Update existing
				updatedModels = append(updatedModels, modelCfg)
			}
			// If isDelete, we skip appending, effectively removing it
		} else {
			updatedModels = append(updatedModels, existingModel)
		}
	}

	if !found && !isDelete { // Add new model
		updatedModels = append(updatedModels, modelCfg)
	}

	fullRuntimeConfig.Models = updatedModels
	fullRuntimeConfig.LastUpdated = time.Now().UTC()

	runtimeConfigData, marshalErr := json.Marshal(fullRuntimeConfig)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal full RuntimeConfig for model update: %w", marshalErr)
	}

	const runtimeConfigKey = "config/runtime/current"
	if errStoreRuntime := h.store.Set(ctx, runtimeConfigKey, runtimeConfigData); errStoreRuntime != nil {
		return fmt.Errorf("failed to store updated RuntimeConfig to '%s' for model change: %w", runtimeConfigKey, errStoreRuntime)
	}
	log.Printf("Admin: Updated RuntimeConfig in store ('%s') due to model change for ID %s.", runtimeConfigKey, modelCfg.ID)
	return nil
}

// --- IAM: Service Account API Key Handlers ---

// CreateServiceAccountAPIKey handles POST /admin/iam/serviceaccounts/{serviceAccountID}/apikeys
func (h *Handler) CreateServiceAccountAPIKey(w http.ResponseWriter, r *http.Request) {
	serviceAccountID := chi.URLParam(r, "serviceAccountID")
	if serviceAccountID == "" {
		http.Error(w, "Service Account ID parameter is required", http.StatusBadRequest)
		return
	}

	// First, check if the service account exists
	_, err := h.iamService.GetServiceAccount(r.Context(), serviceAccountID)
	if err != nil {
		if errors.Is(err, iam.ErrServiceAccountNotFound) {
			http.Error(w, "Service account not found: "+serviceAccountID, http.StatusNotFound)
		} else {
			log.Printf("Admin: CreateServiceAccountAPIKey - Error checking SA ID '%s': %v", serviceAccountID, err)
			http.Error(w, "Failed to validate service account: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	var req CreateUserAPIKeyRequest // Re-use the same request structure for API key creation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var expiresAtTime time.Time
	if req.ExpiresAt != "" {
		parsedTime, timeParseErr := time.Parse(time.RFC3339, req.ExpiresAt)
		if timeParseErr != nil {
			http.Error(w, "Invalid expires_at format, use RFC3339 (e.g., YYYY-MM-DDTHH:MM:SSZ): "+timeParseErr.Error(), http.StatusBadRequest)
			return
		}
		expiresAtTime = parsedTime
	}

	// TODO: Validate RoleNames if provided (check if roles exist in h.iamService.roles)

	// Use serviceAccountID as the 'userID' parameter for GenerateAPIKey
	rawKey, apiKeyMeta, err := h.iamService.GenerateAPIKey(r.Context(), serviceAccountID, req.Name, req.RoleNames, expiresAtTime)
	if err != nil {
		log.Printf("Admin: CreateServiceAccountAPIKey - Error generating API key for SA '%s': %v", serviceAccountID, err)
		http.Error(w, "Failed to generate API key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	responseKeyMeta := &iam.APIKey{
		ID:         apiKeyMeta.ID,
		UserID:     apiKeyMeta.UserID, // This will be the serviceAccountID
		Name:       apiKeyMeta.Name,
		RoleNames:  apiKeyMeta.RoleNames,
		ExpiresAt:  apiKeyMeta.ExpiresAt,
		LastUsedAt: apiKeyMeta.LastUsedAt,
		CreatedAt:  apiKeyMeta.CreatedAt,
		Revoked:    apiKeyMeta.Revoked,
	}

	response := CreateUserAPIKeyResponse{ // Re-use response structure
		RawAPIKey: rawKey,
		APIKey:    responseKeyMeta,
	}

	log.Printf("Admin: Created API Key ID %s for Service Account ID %s", apiKeyMeta.ID, serviceAccountID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// ListServiceAccountAPIKeys handles GET /admin/iam/serviceaccounts/{serviceAccountID}/apikeys
func (h *Handler) ListServiceAccountAPIKeys(w http.ResponseWriter, r *http.Request) {
	serviceAccountID := chi.URLParam(r, "serviceAccountID")
	if serviceAccountID == "" {
		http.Error(w, "Service Account ID parameter is required", http.StatusBadRequest)
		return
	}

	// First, check if the service account exists
	_, err := h.iamService.GetServiceAccount(r.Context(), serviceAccountID)
	if err != nil {
		if errors.Is(err, iam.ErrServiceAccountNotFound) {
			http.Error(w, "Service account not found: "+serviceAccountID, http.StatusNotFound)
		} else {
			log.Printf("Admin: ListServiceAccountAPIKeys - Error checking SA ID '%s': %v", serviceAccountID, err)
			http.Error(w, "Failed to validate service account: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Use serviceAccountID as the 'userID' parameter for ListUserAPIKeys
	apiKeyMetas, err := h.iamService.ListUserAPIKeys(r.Context(), serviceAccountID)
	if err != nil {
		// This path should ideally not be hit if GetServiceAccount above succeeded,
		// as ListUserAPIKeys also checks for principal existence (though as a User).
		// For robustness, handle it.
		log.Printf("Admin: ListServiceAccountAPIKeys error for SA ID '%s': %v", serviceAccountID, err)
		http.Error(w, "Failed to list API keys for service account: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sanitizedKeys := make([]*iam.APIKey, 0, len(apiKeyMetas))
	for _, keyMeta := range apiKeyMetas {
		sanitizedKeys = append(sanitizedKeys, &iam.APIKey{
			ID:         keyMeta.ID,
			UserID:     keyMeta.UserID, // This will be the serviceAccountID
			Name:       keyMeta.Name,
			RoleNames:  keyMeta.RoleNames,
			ExpiresAt:  keyMeta.ExpiresAt,
			LastUsedAt: keyMeta.LastUsedAt,
			CreatedAt:  keyMeta.CreatedAt,
			Revoked:    keyMeta.Revoked,
		})
	}

	response := struct {
		APIKeys []*iam.APIKey `json:"api_keys"`
		Count   int           `json:"count"`
	}{
		APIKeys: sanitizedKeys,
		Count:   len(sanitizedKeys),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// --- Secret Handlers ---

// CreateSecretRequest defines the payload for creating a new secret.
type CreateSecretRequest struct {
	ID    string `json:"id"`    // User-defined ID for the secret
	Value string `json:"value"` // The secret value itself
	// Potentially add Description or Tags here if supported by SecretManagementService
}

// CreateSecret handles POST /admin/secrets
func (h *Handler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	var req CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		http.Error(w, "Secret ID is required", http.StatusBadRequest)
		return
	}
	if req.Value == "" {
		http.Error(w, "Secret value is required", http.StatusBadRequest)
		return
	}

	// Validate Secret ID format (e.g., no spaces, certain characters)
	// For now, assume basic validation is handled by secretManager or is not strict.
	// A common pattern is to prefix system-generated IDs, but here user provides it.

	err := h.secretManager.StoreSecret(r.Context(), req.ID, req.Value)
	if err != nil {
		// Check for specific errors from secretManager if they exist (e.g., ID already exists if not overwriting)
		log.Printf("Admin: CreateSecret - Error storing secret ID '%s': %v", req.ID, err)
		http.Error(w, "Failed to store secret: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Admin: Created/Updated Secret: ID=%s", req.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // Or http.StatusOK if it's an update/overwrite
	json.NewEncoder(w).Encode(map[string]string{"id": req.ID, "status": "created/updated"})
}

// SecretMetadataResponse defines metadata for a secret (excluding the value).
// This should align with secrets.SecretMetadata.
type SecretMetadataResponse struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	ProviderID string    `json:"provider_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	// UpdatedAt and Description could be added if present in secrets.SecretMetadata
}

// ListSecretsMetadata handles GET /admin/secrets
// This should list metadata about secrets, not their actual values.
func (h *Handler) ListSecretsMetadata(w http.ResponseWriter, r *http.Request) {
	// Assuming secretManager has a method like ListSecretsMetadata() ([]SecretMetadata, error)
	// This method needs to be added to the secrets.SecretManagementService interface and its implementations.
	// For now, if such a method doesn't exist, this will be a placeholder.

	metadataList, err := h.secretManager.ListSecretsMetadata(r.Context())
	if err != nil {
		log.Printf("Admin: ListSecretsMetadata - Error: %v", err)
		// Check if the error indicates "not implemented" for specific backends like Vault
		if strings.Contains(err.Error(), "not yet implemented") || strings.Contains(err.Error(), "not implemented") {
			http.Error(w, "Listing secrets metadata not implemented for the configured secret backend.", http.StatusNotImplemented)
		} else {
			http.Error(w, "Failed to list secrets metadata: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	responseSecrets := make([]SecretMetadataResponse, len(metadataList))
	for i, meta := range metadataList {
		responseSecrets[i] = SecretMetadataResponse{
			ID:         meta.ID,
			Name:       meta.Name,
			Type:       meta.Type,
			ProviderID: meta.ProviderID,
			CreatedAt:  meta.CreatedAt,
		}
	}

	response := struct {
		Secrets []SecretMetadataResponse `json:"secrets"`
		Count   int                      `json:"count"`
	}{
		Secrets: responseSecrets,
		Count:   len(responseSecrets),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DeleteSecret handles DELETE /admin/secrets/{secretID}
func (h *Handler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	secretID := chi.URLParam(r, "secretID")
	if secretID == "" {
		http.Error(w, "Secret ID parameter is required", http.StatusBadRequest)
		return
	}

	err := h.secretManager.DeleteSecret(r.Context(), secretID)
	if err != nil {
		// Handle specific errors like "not found"
		if errors.Is(err, store.ErrNotFound) { // Assuming DeleteSecret might return store.ErrNotFound
			http.Error(w, "Secret not found: "+secretID, http.StatusNotFound)
		} else if strings.Contains(err.Error(), "not yet implemented") || strings.Contains(err.Error(), "not implemented") {
			http.Error(w, "Deleting secrets not implemented for the configured secret backend.", http.StatusNotImplemented)
		} else {
			log.Printf("Admin: DeleteSecret - Error deleting secret ID '%s': %v", secretID, err)
			http.Error(w, "Failed to delete secret: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("Admin: Deleted Secret: ID=%s", secretID)
	w.WriteHeader(http.StatusNoContent)
}

// TODO: Add other IAM handlers (APIKeys - specifically for Service Accounts if different)
// TODO: Add Secret handlers (Create, List, Delete) // Create is added, List and Delete are placeholders

// --- Plugin Handlers ---

// PluginInstanceMetadataResponse defines the metadata for a plugin instance.
type PluginInstanceMetadataResponse struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // Type of the plugin (e.g., "custom_auth", "rate_limiter")
	Enabled     bool                   `json:"enabled"`
	Status      string                 `json:"status,omitempty"`      // e.g., "running", "stopped", "error"
	Address     string                 `json:"address,omitempty"`     // Address of the plugin gRPC server
	Config      map[string]interface{} `json:"config,omitempty"`      // Non-sensitive parts of config, or just an indication if configured
	Version     string                 `json:"version,omitempty"`     // Plugin version, if available
	Description string                 `json:"description,omitempty"` // Plugin description
}

// ListPlugins handles GET /admin/plugins
func (h *Handler) ListPlugins(w http.ResponseWriter, r *http.Request) {
	// Assume h.pluginMgr has a method like ListPluginInstanceMetadata() ([]pluginruntime.PluginInstanceMetadata, error)
	// This method needs to be added to pluginruntime.ManagerInterface and its implementation.
	// pluginruntime.PluginInstanceMetadata would be a struct in pluginruntime package.

	// Placeholder until pluginMgr interface is updated:
	// We can iterate over h.configMgr.GetCurrentConfig().Plugins for basic info.
	currentCfg := h.configMgr.GetCurrentConfig()
	if currentCfg == nil {
		http.Error(w, "Gateway configuration not available", http.StatusInternalServerError)
		return
	}

	responsePlugins := make([]PluginInstanceMetadataResponse, 0, len(currentCfg.Plugins))
	for _, pDef := range currentCfg.Plugins {
		// Try to get live status from pluginMgr if possible (requires new pluginMgr method)
		// liveStatus := "unknown" // Default
		// if h.pluginMgr != nil {
		//  status, err := h.pluginMgr.GetPluginInstanceStatus(pDef.ID) // Assuming pluginMgr uses PluginDefinition ID
		//  if err == nil { liveStatus = status }
		// }

		responsePlugins = append(responsePlugins, PluginInstanceMetadataResponse{
			ID:          pDef.ID,
			Name:        pDef.Name,
			Type:        pDef.Type,
			Enabled:     pDef.Enabled,
			Address:     pDef.ExecutablePath, // Using ExecutablePath as Address for now
			Description: pDef.Description,
			Version:     pDef.Version,
			// Status: liveStatus, // Would come from a live check
		})
	}

	response := struct {
		Plugins []PluginInstanceMetadataResponse `json:"plugins"`
		Count   int                              `json:"count"`
	}{
		Plugins: responsePlugins,
		Count:   len(responsePlugins),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetPlugin handles GET /admin/plugins/{pluginID}
func (h *Handler) GetPlugin(w http.ResponseWriter, r *http.Request) {
	pluginID := chi.URLParam(r, "pluginID")
	if pluginID == "" {
		http.Error(w, "Plugin ID parameter is required", http.StatusBadRequest)
		return
	}

	// Assume h.pluginMgr has GetPluginInstanceMetadata(pluginID string) (*pluginruntime.PluginInstanceMetadata, error)
	// Placeholder:
	currentCfg := h.configMgr.GetCurrentConfig()
	if currentCfg == nil {
		http.Error(w, "Gateway configuration not available", http.StatusInternalServerError)
		return
	}
	for _, pDef := range currentCfg.Plugins {
		if pDef.ID == pluginID {
			// liveStatus := "unknown"
			// if h.pluginMgr != nil { ... }
			resp := PluginInstanceMetadataResponse{
				ID:          pDef.ID,
				Name:        pDef.Name,
				Type:        pDef.Type,
				Enabled:     pDef.Enabled,
				Address:     pDef.ExecutablePath,
				Description: pDef.Description,
				Version:     pDef.Version,
				// Status: liveStatus,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	http.Error(w, "Plugin not found: "+pluginID, http.StatusNotFound)
}

// UpdatePluginRequest defines the payload for updating a plugin (e.g., enabling/disabling).
type UpdatePluginRequest struct {
	Enabled *bool `json:"enabled,omitempty"` // Pointer to distinguish true/false from not provided
	// Potentially other updatable fields like config (if managed this way)
}

// UpdatePlugin handles PATCH /admin/plugins/{pluginID}
func (h *Handler) UpdatePlugin(w http.ResponseWriter, r *http.Request) {
	pluginID := chi.URLParam(r, "pluginID")
	if pluginID == "" {
		http.Error(w, "Plugin ID parameter is required", http.StatusBadRequest)
		return
	}

	var req UpdatePluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Enabled == nil {
		http.Error(w, "No update operation specified (e.g., 'enabled' field missing)", http.StatusBadRequest)
		return
	}

	// Assume h.pluginMgr has UpdatePluginInstanceStatus(pluginID string, enabled bool) error
	// This method needs to be added to pluginruntime.ManagerInterface and its implementation.
	// It should also persist this change to the config.PluginInstanceConfig and notify ConfigManager.

	// Placeholder until pluginMgr interface is updated:
	// This would involve finding the plugin in currentCfg.Plugins, updating its Enabled field,
	// then re-saving the entire RuntimeConfig.
	currentCfg := h.configMgr.GetCurrentConfig()
	if currentCfg == nil {
		http.Error(w, "Gateway configuration not available", http.StatusInternalServerError)
		return
	}

	var foundPluginDef *config.PluginDefinition
	pluginIndex := -1
	for i := range currentCfg.Plugins {
		if currentCfg.Plugins[i].ID == pluginID {
			foundPluginDef = &currentCfg.Plugins[i]
			pluginIndex = i
			break
		}
	}

	if foundPluginDef == nil {
		http.Error(w, "Plugin definition not found: "+pluginID, http.StatusNotFound)
		return
	}

	currentCfg.Plugins[pluginIndex].Enabled = *req.Enabled
	// PluginDefinition does not have UpdatedAt, so we don't set it here.
	// The RuntimeConfig.LastUpdated will be set.

	// Persist the change by updating the full RuntimeConfig
	currentCfg.LastUpdated = time.Now().UTC()
	runtimeConfigData, marshalErr := json.Marshal(currentCfg)
	if marshalErr != nil {
		log.Printf("Admin: UpdatePlugin - Error marshalling full RuntimeConfig: %v", marshalErr)
		http.Error(w, "Failed to process configuration update", http.StatusInternalServerError)
		return
	}
	const runtimeConfigKey = "config/runtime/current"
	if errStoreRuntime := h.store.Set(r.Context(), runtimeConfigKey, runtimeConfigData); errStoreRuntime != nil {
		log.Printf("Admin: UpdatePlugin - Error storing updated RuntimeConfig: %v", errStoreRuntime)
		http.Error(w, "Failed to save configuration update", http.StatusInternalServerError)
		return
	}

	log.Printf("Admin: Updated Plugin ID %s: Enabled status set to %v", pluginID, *req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(foundPluginDef) // Respond with the updated plugin config part
}

// GetPluginConfigSchema handles GET /admin/plugins/{pluginID}/configschema
func (h *Handler) GetPluginConfigSchema(w http.ResponseWriter, r *http.Request) {
	pluginID := chi.URLParam(r, "pluginID") // Or pluginType if schema is per type
	if pluginID == "" {
		http.Error(w, "Plugin ID (or type) parameter is required", http.StatusBadRequest)
		return
	}

	// Assume h.pluginMgr has GetPluginTypeConfigSchema(pluginType string) (json.RawMessage, error)
	// or GetPluginInstanceConfigSchema(instanceID string) (json.RawMessage, error)
	// This method needs to be added to pluginruntime.ManagerInterface and its implementation.

	// Placeholder:
	// Find plugin type from config
	pluginType := ""
	currentCfg := h.configMgr.GetCurrentConfig()
	if currentCfg != nil {
		for _, pDef := range currentCfg.Plugins {
			if pDef.ID == pluginID {
				pluginType = pDef.Type
				break
			}
		}
	}
	if pluginType == "" {
		http.Error(w, "Plugin definition not found or type unknown: "+pluginID, http.StatusNotFound)
		return
	}

	// Example schema (replace with actual schema loading logic)
	var schema json.RawMessage
	if pluginType == "custom_auth" { // Example
		schema = json.RawMessage(`{"type": "object", "properties": {"api_key_header": {"type": "string"}, "valid_keys_secret_id": {"type": "string"}}}`)
	} else {
		schema = json.RawMessage(`{"type": "object", "description": "No specific schema defined for this plugin type."}`)
	}

	log.Printf("Admin: GetPluginConfigSchema for Plugin ID/Type %s", pluginID)
	w.Header().Set("Content-Type", "application/json")
	w.Write(schema)
}

// TODO: Add Plugin handlers (List, Get, Update, GetConfigSchema) // Partially implemented with placeholders
// TODO: Add Proxy handlers for embeddings, audio, tools if they are part of this admin server.
//       Currently, they are placeholderHandler in server.go, suggesting they might be separate.
