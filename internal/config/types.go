package config

import "time"

// RuntimeConfig is the top-level configuration structure for OpenPons.
// It holds all dynamic configurations loaded from the datastore.
type RuntimeConfig struct {
	Providers   []ProviderConfig   `json:"providers" yaml:"providers"`
	Models      []ModelConfig      `json:"models" yaml:"models"`
	Tools       []ToolConfig       `json:"tools,omitempty" yaml:"tools,omitempty"`   // Added
	Agents      []AgentConfig      `json:"agents,omitempty" yaml:"agents,omitempty"` // Added
	Routes      []RouteConfig      `json:"routes" yaml:"routes"`
	Plugins     []PluginDefinition `json:"plugins" yaml:"plugins"` // Definitions of available plugins
	IAMConfig   IAMConfig          `json:"iam_config" yaml:"iam_config"`
	Settings    GatewaySettings    `json:"settings" yaml:"settings"`
	LastUpdated time.Time          `json:"last_updated" yaml:"last_updated"` // For versioning/tracking
}

// ProviderType defines the kind of upstream provider.
type ProviderType string

const (
	ProviderTypeLLM           ProviderType = "llm"
	ProviderTypeToolServer    ProviderType = "tool_server"    // MCP
	ProviderTypeAgentPlatform ProviderType = "agent_platform" // A2A
)

// ProviderConfig defines the configuration for an upstream service provider.
type ProviderConfig struct {
	ID                  string       `json:"id" yaml:"id"`                                                           // Unique ID (e.g., UUID)
	Name                string       `json:"name" yaml:"name"`                                                       // User-friendly name (e.g., "openai-main-us-east")
	Type                ProviderType `json:"type" yaml:"type"`                                                       // llm, tool_server, agent_platform
	Status              string       `json:"status" yaml:"status"`                                                   // active, disabled, error
	CredentialsSecretID string       `json:"credentials_secret_id,omitempty" yaml:"credentials_secret_id,omitempty"` // Ref to secret in secret store

	// Type-specific configurations
	LLMConfig         *LLMProviderConfig   `json:"llm_config,omitempty" yaml:"llm_config,omitempty"`
	MCPToolConfig     *MCPToolServerConfig `json:"mcp_tool_config,omitempty" yaml:"mcp_tool_config,omitempty"`
	A2APlatformConfig *A2APlatformConfig   `json:"a2a_platform_config,omitempty" yaml:"a2a_platform_config,omitempty"`

	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

type LLMProviderConfig struct {
	APIBase       string   `json:"api_base" yaml:"api_base"`                                 // Base URL for the LLM provider
	DefaultModels []string `json:"default_models,omitempty" yaml:"default_models,omitempty"` // Default models to expose if not explicitly defined
	// Provider-specific fields, e.g., Azure APIType, APIVersion
	AzureAPIType    string `json:"azure_api_type,omitempty" yaml:"azure_api_type,omitempty"`
	AzureAPIVersion string `json:"azure_api_version,omitempty" yaml:"azure_api_version,omitempty"`
	// VertexAI-specific fields
	VertexAI *VertexAIConfig `json:"vertex_ai,omitempty" yaml:"vertex_ai,omitempty"`
}

// VertexAIConfig holds VertexAI-specific configuration
type VertexAIConfig struct {
	ProjectID string `json:"project_id" yaml:"project_id"` // GCP Project ID
	Location  string `json:"location" yaml:"location"`     // GCP Location (e.g., us-central1)
}

type MCPToolServerConfig struct {
	ServerAddress string `json:"server_address" yaml:"server_address"` // e.g., "grpc://my-mcp-server:port" or "stdio:command arg1 arg2"
	// mTLS client cert secret ID, etc.
}

type A2APlatformConfig struct {
	HubAddress string `json:"hub_address,omitempty" yaml:"hub_address,omitempty"` // Address of an A2A hub or a specific agent
	// Auth details for A2A
}

// ModelConfig defines a specific model available through a provider.
type ModelConfig struct {
	ID                     string            `json:"id" yaml:"id"`                                   // User-facing ID (e.g., "openai-gpt4o")
	ProviderID             string            `json:"provider_id" yaml:"provider_id"`                 // References ProviderConfig.ID
	UpstreamModelName      string            `json:"upstream_model_name" yaml:"upstream_model_name"` // Actual model name for the provider (e.g., "gpt-4o")
	Version                string            `json:"version,omitempty" yaml:"version,omitempty"`     // Optional version tag
	ContextWindow          int               `json:"context_window,omitempty" yaml:"context_window,omitempty"`
	InputPricingPerToken   float64           `json:"input_pricing_per_token,omitempty" yaml:"input_pricing_per_token,omitempty"`
	OutputPricingPerToken  float64           `json:"output_pricing_per_token,omitempty" yaml:"output_pricing_per_token,omitempty"`
	InputPricingPerSecond  float64           `json:"input_pricing_per_second,omitempty" yaml:"input_pricing_per_second,omitempty"` // For time-based models
	OutputPricingPerSecond float64           `json:"output_pricing_per_second,omitempty" yaml:"output_pricing_per_second,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"` // Tags, capabilities (e.g., "supports_tools:true")
	Status                 string            `json:"status" yaml:"status"`                         // active, deprecated, disabled
	CreatedAt              time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at" yaml:"updated_at"`
}

// RouteConfig defines how incoming requests are routed to upstream services.
type RouteConfig struct {
	ID                string         `json:"id" yaml:"id"`                                                     // Unique ID (e.g., UUID)
	Name              string         `json:"name" yaml:"name"`                                                 // User-friendly name (e.g., "summarize-text-prod")
	Priority          int            `json:"priority,omitempty" yaml:"priority,omitempty"`                     // Lower value means higher priority
	Protocol          ProtocolType   `json:"protocol" yaml:"protocol"`                                         // http_llm, mcp_tool, a2a_task
	Match             RouteMatch     `json:"match" yaml:"match"`                                               // Criteria for matching requests to this route
	Targets           []RouteTarget  `json:"targets" yaml:"targets"`                                           // List of upstream targets
	Policy            RoutePolicy    `json:"policy,omitempty" yaml:"policy,omitempty"`                         // Routing policies
	AllowedPrincipals []PrincipalRef `json:"allowed_principals,omitempty" yaml:"allowed_principals,omitempty"` // Who can access this route
	Plugins           RoutePlugins   `json:"plugins,omitempty" yaml:"plugins,omitempty"`                       // Plugins applied to this route
	CreatedAt         time.Time      `json:"created_at" yaml:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at" yaml:"updated_at"`
}

type ProtocolType string

const (
	ProtocolHTTPLLM ProtocolType = "http_llm"
	ProtocolMCPTool ProtocolType = "mcp_tool"
	ProtocolA2ATask ProtocolType = "a2a_task"
)

type RouteMatch struct {
	PathPrefix string            `json:"path_prefix,omitempty" yaml:"path_prefix,omitempty"` // e.g., "/proxy/models/"
	ModelID    string            `json:"model_id,omitempty" yaml:"model_id,omitempty"`       // Matches ModelConfig.ID for LLM routes
	ToolID     string            `json:"tool_id,omitempty" yaml:"tool_id,omitempty"`         // Matches ToolConfig.ID for MCP routes
	AgentID    string            `json:"agent_id,omitempty" yaml:"agent_id,omitempty"`       // Matches AgentConfig.ID for A2A routes
	TaskName   string            `json:"task_name,omitempty" yaml:"task_name,omitempty"`     // For A2A routes
	Headers    map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`         // Match on request headers
}

type RouteTarget struct {
	Ref    string `json:"ref" yaml:"ref"`       // ID of ModelConfig, ToolConfig, or AgentConfig
	Weight int    `json:"weight" yaml:"weight"` // 0-100, for weighted load balancing
	// Version string `json:"version,omitempty" yaml:"version,omitempty"` // Specific version of the target
}

const (
	StrategyWeightedRoundRobin = "weighted_round_robin"
	StrategyFailover           = "failover"
	StrategyLeastPending       = "least_pending"
	// Default strategy if not specified could be weighted_round_robin
)

type RoutePolicy struct {
	Strategy       string                `json:"strategy,omitempty" yaml:"strategy,omitempty"` // weighted_round_robin, least_pending, failover
	RetryOnFailure bool                  `json:"retry_on_failure,omitempty" yaml:"retry_on_failure,omitempty"`
	RetryAttempts  int                   `json:"retry_attempts,omitempty" yaml:"retry_attempts,omitempty"` // Default: 3
	TimeoutMs      int                   `json:"timeout_ms,omitempty" yaml:"timeout_ms,omitempty"`         // Default: 30000
	CircuitBreaker *CircuitBreakerPolicy `json:"circuit_breaker,omitempty" yaml:"circuit_breaker,omitempty"`
}

type CircuitBreakerPolicy struct {
	ConsecutiveErrors int `json:"consecutive_errors" yaml:"consecutive_errors"` // Num errors to open breaker
	IntervalMs        int `json:"interval_ms" yaml:"interval_ms"`               // Time interval for counting errors
	TimeoutMs         int `json:"timeout_ms" yaml:"timeout_ms"`                 // Time breaker stays open
}

type PrincipalRef struct {
	Type string `json:"type" yaml:"type"` // user, group, service_account
	ID   string `json:"id" yaml:"id"`     // UUID of the principal
}

type RoutePlugins struct {
	Pre  []PluginInstanceConfig `json:"pre,omitempty" yaml:"pre,omitempty"`   // Plugins executed before routing
	Post []PluginInstanceConfig `json:"post,omitempty" yaml:"post,omitempty"` // Plugins executed after response from upstream
}

// PluginInstanceConfig defines an instance of a plugin applied to a route, with its specific config.
type PluginInstanceConfig struct {
	ID     string                 `json:"id" yaml:"id"`                             // Plugin ID (name@version, e.g., "pii-masker@1.2.0")
	Config map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"` // Plugin-specific configuration
	Order  int                    `json:"order,omitempty" yaml:"order,omitempty"`   // Execution order for plugins in the same hook
}

// PluginDefinition describes an available plugin in the system.
type PluginDefinition struct {
	ID          string `json:"id" yaml:"id"`           // Unique ID (e.g., "pii-masker@1.2.0" or just "pii-masker")
	Name        string `json:"name" yaml:"name"`       // User-friendly name
	Version     string `json:"version" yaml:"version"` // Semantic version
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Type        string `json:"type" yaml:"type"`       // e.g., "guardrail", "tracing", "auth"
	Enabled     bool   `json:"enabled" yaml:"enabled"` // Globally enabled/disabled
	// ConfigSchema map[string]interface{} `json:"config_schema,omitempty" yaml:"config_schema,omitempty"` // JSON schema for its configuration
	// Path to executable or WASM module if out-of-process
	ExecutablePath string `json:"executable_path,omitempty" yaml:"executable_path,omitempty"`
}

// IAMConfig holds all IAM related configurations.
type IAMConfig struct {
	Users           []UserConfig           `json:"users" yaml:"users"`
	Groups          []GroupConfig          `json:"groups" yaml:"groups"`
	Roles           []RoleConfig           `json:"roles" yaml:"roles"`
	RoleBindings    []RoleBindingConfig    `json:"role_bindings" yaml:"role_bindings"`
	ServiceAccounts []ServiceAccountConfig `json:"service_accounts,omitempty" yaml:"service_accounts,omitempty"` // Added
	// OIDC provider configurations
	OIDCProviders []OIDCProviderConfig `json:"oidc_providers,omitempty" yaml:"oidc_providers,omitempty"`
}

// ServiceAccountConfig defines the configuration for a service account.
type ServiceAccountConfig struct {
	ID          string    `json:"id" yaml:"id"`                                       // UUID, typically prefixed like "sa-"
	DisplayName string    `json:"display_name" yaml:"display_name"`                   // User-friendly name
	Description string    `json:"description,omitempty" yaml:"description,omitempty"` // Optional description
	Status      string    `json:"status" yaml:"status"`                               // "active" or "disabled"
	CreatedAt   time.Time `json:"created_at" yaml:"created_at"`                       // Timestamp of creation
	UpdatedAt   time.Time `json:"updated_at" yaml:"updated_at"`                       // Timestamp of last update
	// TODO: Potentially add a field for associated API key IDs if managed directly, or this is handled elsewhere.
}

type UserConfig struct {
	ID       string   `json:"id" yaml:"id"` // UUID
	Email    string   `json:"email" yaml:"email"`
	GroupIDs []string `json:"group_ids,omitempty" yaml:"group_ids,omitempty"` // List of Group IDs
	// APIKeys, status, etc.
	Status    string    `json:"status" yaml:"status"` // active, disabled
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

type GroupConfig struct {
	ID        string    `json:"id" yaml:"id"` // UUID
	Name      string    `json:"name" yaml:"name"`
	MemberIDs []string  `json:"member_ids,omitempty" yaml:"member_ids,omitempty"` // List of User IDs
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

type RoleConfig struct {
	Name        string       `json:"name" yaml:"name"` // Unique role name (e.g., "admin", "developer")
	Permissions []Permission `json:"permissions" yaml:"permissions"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
}

type Permission string // e.g., "models:read", "routes:write", "proxy:invoke:model_xyz"

type RoleBindingConfig struct {
	ID            string      `json:"id" yaml:"id"`                         // UUID
	PrincipalType string      `json:"principal_type" yaml:"principal_type"` // "user" or "group"
	PrincipalID   string      `json:"principal_id" yaml:"principal_id"`     // User.ID or Group.ID
	RoleName      string      `json:"role_name" yaml:"role_name"`           // Role.Name
	Scope         ScopeConfig `json:"scope" yaml:"scope"`
	CreatedAt     time.Time   `json:"created_at" yaml:"created_at"`
}

type ScopeConfig struct {
	Type  string `json:"type" yaml:"type"`                       // GLOBAL, NAMESPACE, ROUTE, MODEL, PROVIDER
	Value string `json:"value,omitempty" yaml:"value,omitempty"` // ID of the resource if not GLOBAL/NAMESPACE, or namespace name
}

type OIDCProviderConfig struct {
	ID                   string            `json:"id" yaml:"id"`
	IssuerURL            string            `json:"issuer_url" yaml:"issuer_url"`
	ClientID             string            `json:"client_id" yaml:"client_id"`
	ClientSecretSecretID string            `json:"client_secret_secret_id" yaml:"client_secret_secret_id"`   // Ref to secret
	RedirectURL          string            `json:"redirect_url" yaml:"redirect_url"`                         // Callback URL for this client
	Scopes               []string          `json:"scopes,omitempty" yaml:"scopes,omitempty"`                 // e.g. ["openid", "email", "profile", "groups"]
	ClaimMappings        map[string]string `json:"claim_mappings,omitempty" yaml:"claim_mappings,omitempty"` // e.g. {"email_claim": "custom_email_claim_name"}
	GroupMappings        map[string]string `json:"group_mappings,omitempty" yaml:"group_mappings,omitempty"` // OIDC Group Name -> OpenPons Group ID
}

// GatewaySettings holds global settings for the gateway.
type GatewaySettings struct {
	DefaultTimeoutMs                 int `json:"default_timeout_ms,omitempty" yaml:"default_timeout_ms,omitempty"`
	DefaultRetryAttempts             int `json:"default_retry_attempts,omitempty" yaml:"default_retry_attempts,omitempty"`
	PluginHealthCheckIntervalSeconds int `json:"plugin_health_check_interval_seconds,omitempty" yaml:"plugin_health_check_interval_seconds,omitempty"` // Interval in seconds
	// Other global settings
}

// ToolConfig defines a specific tool available through an MCP provider.
type ToolConfig struct {
	ID                string                 `json:"id" yaml:"id"`                                 // User-facing ID (e.g., "filesystem-list-dir")
	ProviderID        string                 `json:"provider_id" yaml:"provider_id"`               // References ProviderConfig.ID (type: tool_server)
	UpstreamToolName  string                 `json:"upstream_tool_name" yaml:"upstream_tool_name"` // Actual tool name on the MCP server
	Description       string                 `json:"description,omitempty" yaml:"description,omitempty"`
	InputSchema       map[string]interface{} `json:"input_schema,omitempty" yaml:"input_schema,omitempty"`             // JSON Schema for tool arguments
	SupportsStreaming bool                   `json:"supports_streaming,omitempty" yaml:"supports_streaming,omitempty"` // Whether the tool supports streaming invocation
	Status            string                 `json:"status" yaml:"status"`                                             // active, disabled
	CreatedAt         time.Time              `json:"created_at" yaml:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" yaml:"updated_at"`
}

// AgentConfig defines a specific A2A agent.
type AgentConfig struct {
	ID              string    `json:"id" yaml:"id"`                                         // User-facing ID
	ProviderID      string    `json:"provider_id" yaml:"provider_id"`                       // References ProviderConfig.ID (type: agent_platform)
	UpstreamAgentID string    `json:"upstream_agent_id" yaml:"upstream_agent_id"`           // Actual agent ID on the platform
	EndpointURL     string    `json:"endpoint_url,omitempty" yaml:"endpoint_url,omitempty"` // If directly addressable
	Capabilities    []string  `json:"capabilities,omitempty" yaml:"capabilities,omitempty"` // List of tasks/capabilities
	Status          string    `json:"status" yaml:"status"`                                 // active, disabled
	CreatedAt       time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" yaml:"updated_at"`
}

// APIKeyConfig stores metadata about an API key.
// The actual secret key value is not stored here directly.
// Instead, a hash or a reference to a secret in a secure store is used.
type APIKeyConfig struct {
	ID                string     `json:"id" yaml:"id"`                                     // Unique ID for the API key entry (e.g., "ak_uuid")
	UserID            string     `json:"user_id" yaml:"user_id"`                           // ID of the user or service account this key belongs to
	Name              string     `json:"name,omitempty" yaml:"name,omitempty"`             // User-defined name for the key
	KeyPrefix         string     `json:"key_prefix" yaml:"key_prefix"`                     // First few characters of the key for identification (e.g., "opk_user_...")
	HashedKeySecretID string     `json:"hashed_key_secret_id" yaml:"hashed_key_secret_id"` // ID of the secret in SecretManager holding the hashed key
	Status            string     `json:"status" yaml:"status"`                             // "active", "revoked"
	CreatedAt         time.Time  `json:"created_at" yaml:"created_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`     // Optional expiration time
	LastUsedAt        *time.Time `json:"last_used_at,omitempty" yaml:"last_used_at,omitempty"` // Optional: when the key was last used
	RevokedAt         *time.Time `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`     // Optional: when the key was revoked
}
