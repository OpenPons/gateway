package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3" // For YAML parsing
)

// StaticGRPCConfig holds static GRPC server configuration.
type StaticGRPCConfig struct {
	Addr string `yaml:"addr"`
}

// StaticAdminConfig holds static Admin server configuration.
type StaticAdminConfig struct {
	Addr string `yaml:"addr"`
}

// StaticLogConfig holds static logging configuration.
type StaticLogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// StaticDBConfig holds static database configuration.
type StaticDBConfig struct {
	Path string `yaml:"path"`
}

// StaticOIDCConfig holds static OIDC provider configuration for bootstrap.
type StaticOIDCConfig struct {
	IssuerURI       string        `yaml:"issuer_uri"`
	ClientID        string        `yaml:"client_id"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	Audience        string        `yaml:"audience,omitempty"`
	ScopesSupported []string      `yaml:"scopes_supported,omitempty"`
	GroupsClaim     string        `yaml:"groups_claim,omitempty"`
}

// StaticIAMConfig holds static IAM configuration for bootstrap.
type StaticIAMConfig struct {
	OIDC *StaticOIDCConfig `yaml:"oidc,omitempty"`
}

// StaticOTLPConfig holds static OTLP exporter configuration.
type StaticOTLPConfig struct {
	Endpoint string `yaml:"endpoint"`
}

// StaticTelemetryConfig holds static telemetry configuration.
type StaticTelemetryConfig struct {
	Enabled bool             `yaml:"enabled"`
	OTLP    StaticOTLPConfig `yaml:"otlp"`
}

// StaticProviderConfig holds simplified provider configuration for bootstrap.
type StaticProviderConfig struct {
	Name            string `yaml:"name"`
	Type            string `yaml:"type"`
	APIKeySecret    string `yaml:"api_key_secret,omitempty"`
	DefaultModel    string `yaml:"default_model,omitempty"`
	APIBase         string `yaml:"api_base,omitempty"`
	AzureAPIType    string `yaml:"azure_api_type,omitempty"`
	AzureAPIVersion string `yaml:"azure_api_version,omitempty"`
}

// StaticRouteConfig holds simplified route configuration for bootstrap.
type StaticRouteConfig struct {
	PathPrefix string `yaml:"path_prefix"`
	Provider   string `yaml:"provider"`
}

// StaticConfig is the top-level structure for static configuration loaded from file/env.
type StaticConfig struct {
	Path      string                 `yaml:"-"` // Not from YAML, set internally
	GRPC      StaticGRPCConfig       `yaml:"grpc"`
	Admin     StaticAdminConfig      `yaml:"admin"`
	Log       StaticLogConfig        `yaml:"log"`
	DB        StaticDBConfig         `yaml:"db"`
	IAM       *StaticIAMConfig       `yaml:"iam,omitempty"`
	Telemetry *StaticTelemetryConfig `yaml:"telemetry,omitempty"`
	Providers []StaticProviderConfig `yaml:"providers,omitempty"`
	Routes    []StaticRouteConfig    `yaml:"routes,omitempty"`
}

// Default config values
const (
	defaultConfigPathEnvVar = "OPENPONS_CONFIG_PATH"
	defaultConfigPath       = "/etc/openpons/gateway.yaml" // Fallback if env var not set
	defaultGRPCPort         = ":50051"
	defaultAdminPort        = ":8081"
	defaultLogLevel         = "info"
	defaultLogFormat        = "text"
	defaultDBPath           = "openpons.db"
	defaultOIDCRefresh      = 5 * time.Minute
)

func defaultConfig() *StaticConfig {
	return &StaticConfig{
		GRPC:  StaticGRPCConfig{Addr: defaultGRPCPort},
		Admin: StaticAdminConfig{Addr: defaultAdminPort},
		Log:   StaticLogConfig{Level: defaultLogLevel, Format: defaultLogFormat},
		DB:    StaticDBConfig{Path: defaultDBPath},
		IAM: &StaticIAMConfig{ // Initialize to ensure OIDC can be set by default
			OIDC: &StaticOIDCConfig{
				RefreshInterval: defaultOIDCRefresh,
			},
		},
		Telemetry: &StaticTelemetryConfig{ // Initialize to ensure OTLP can be set
			OTLP: StaticOTLPConfig{},
		},
		Providers: []StaticProviderConfig{},
		Routes:    []StaticRouteConfig{},
	}
}

// Load initializes a new StaticConfig with defaults, then loads from a YAML file.
// Environment variable overrides are handled by MergeEnvOverrides.
func Load() (*StaticConfig, error) {
	cfg := defaultConfig()

	configFilePath := os.Getenv(defaultConfigPathEnvVar)
	if configFilePath == "" {
		configFilePath = defaultConfigPath
	}
	cfg.Path = configFilePath // Store the path that will be attempted

	if _, err := os.Stat(configFilePath); err == nil {
		yamlFile, err := os.ReadFile(configFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configFilePath, err)
		}
		err = yaml.Unmarshal(yamlFile, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal config file %s: %w", configFilePath, err)
		}
	} else if !os.IsNotExist(err) {
		// File exists but couldn't be stated (e.g. permission issue)
		return nil, fmt.Errorf("failed to stat config file %s: %w", configFilePath, err)
	}
	// If file does not exist, we proceed with defaults. Env vars are applied later.

	return cfg, nil
}

// MergeEnvOverrides applies environment variable overrides to a copy of baseCfg.
func MergeEnvOverrides(baseCfg *StaticConfig) (*StaticConfig, error) {
	// Create a new config, starting with defaults, then apply baseCfg, then env.
	// This ensures that if baseCfg is nil, we still have a valid structure.
	cfg := defaultConfig()

	// If baseCfg is provided, "merge" it onto the fresh defaults.
	// This is a simple override; baseCfg fields overwrite default fields.
	if baseCfg != nil {
		// Path
		if baseCfg.Path != "" { // Path is special, usually set by Load or test setup
			cfg.Path = baseCfg.Path
		}
		// GRPC
		if baseCfg.GRPC.Addr != "" {
			cfg.GRPC.Addr = baseCfg.GRPC.Addr
		}
		// Admin
		if baseCfg.Admin.Addr != "" {
			cfg.Admin.Addr = baseCfg.Admin.Addr
		}
		// Log
		if baseCfg.Log.Level != "" {
			cfg.Log.Level = baseCfg.Log.Level
		}
		if baseCfg.Log.Format != "" {
			cfg.Log.Format = baseCfg.Log.Format
		}
		// DB
		if baseCfg.DB.Path != "" {
			cfg.DB.Path = baseCfg.DB.Path
		}

		// IAM (pointer)
		if baseCfg.IAM != nil {
			if cfg.IAM == nil {
				cfg.IAM = &StaticIAMConfig{}
			}
			if baseCfg.IAM.OIDC != nil {
				if cfg.IAM.OIDC == nil {
					cfg.IAM.OIDC = &StaticOIDCConfig{}
				}
				*cfg.IAM.OIDC = *baseCfg.IAM.OIDC // Copy struct contents
			} else {
				cfg.IAM.OIDC = nil // If base has IAM but no OIDC, reflect that
			}
		} else {
			cfg.IAM = nil // If base has no IAM, reflect that
		}

		// Telemetry (pointer)
		if baseCfg.Telemetry != nil {
			if cfg.Telemetry == nil {
				cfg.Telemetry = &StaticTelemetryConfig{}
			}
			*cfg.Telemetry = *baseCfg.Telemetry // Copy struct contents (OTLP is value type inside)
		} else {
			cfg.Telemetry = nil
		}

		// Providers & Routes (slices) - replace if baseCfg has them
		if baseCfg.Providers != nil {
			cfg.Providers = baseCfg.Providers
		}
		if baseCfg.Routes != nil {
			cfg.Routes = baseCfg.Routes
		}
	}

	// Apply environment variables to 'cfg'
	if val := os.Getenv("OPENPONS_GRPC_ADDR"); val != "" {
		cfg.GRPC.Addr = val
	}
	if val := os.Getenv("OPENPONS_ADMIN_ADDR"); val != "" {
		cfg.Admin.Addr = val
	}
	if val := os.Getenv("OPENPONS_LOG_LEVEL"); val != "" {
		cfg.Log.Level = val
	}
	if val := os.Getenv("OPENPONS_LOG_FORMAT"); val != "" {
		cfg.Log.Format = val
	}
	if val := os.Getenv("OPENPONS_DB_PATH"); val != "" {
		cfg.DB.Path = val
	}

	// IAM & OIDC - Initialize if env vars are set and struct is nil
	isOIDCEnvSet := os.Getenv("OPENPONS_IAM_OIDC_ISSUER_URI") != "" ||
		os.Getenv("OPENPONS_IAM_OIDC_CLIENT_ID") != "" ||
		os.Getenv("OPENPONS_IAM_OIDC_REFRESH_INTERVAL") != "" ||
		os.Getenv("OPENPONS_IAM_OIDC_AUDIENCE") != "" ||
		os.Getenv("OPENPONS_IAM_OIDC_SCOPES_SUPPORTED") != "" ||
		os.Getenv("OPENPONS_IAM_OIDC_GROUPS_CLAIM") != ""

	if isOIDCEnvSet {
		if cfg.IAM == nil {
			cfg.IAM = &StaticIAMConfig{}
		}
		if cfg.IAM.OIDC == nil {
			// Initialize with default refresh if creating new due to env var
			cfg.IAM.OIDC = &StaticOIDCConfig{RefreshInterval: defaultOIDCRefresh}
		}
	}
	if cfg.IAM != nil && cfg.IAM.OIDC != nil {
		if val := os.Getenv("OPENPONS_IAM_OIDC_ISSUER_URI"); val != "" {
			cfg.IAM.OIDC.IssuerURI = val
		}
		if val := os.Getenv("OPENPONS_IAM_OIDC_CLIENT_ID"); val != "" {
			cfg.IAM.OIDC.ClientID = val
		}
		if val := os.Getenv("OPENPONS_IAM_OIDC_REFRESH_INTERVAL"); val != "" {
			dur, err := time.ParseDuration(val)
			if err != nil {
				return nil, fmt.Errorf("invalid format for OPENPONS_IAM_OIDC_REFRESH_INTERVAL '%s': %w", val, err)
			}
			cfg.IAM.OIDC.RefreshInterval = dur
		}
		if val := os.Getenv("OPENPONS_IAM_OIDC_AUDIENCE"); val != "" {
			cfg.IAM.OIDC.Audience = val
		}
		if val := os.Getenv("OPENPONS_IAM_OIDC_SCOPES_SUPPORTED"); val != "" {
			cfg.IAM.OIDC.ScopesSupported = strings.Split(val, ",")
		}
		if val := os.Getenv("OPENPONS_IAM_OIDC_GROUPS_CLAIM"); val != "" {
			cfg.IAM.OIDC.GroupsClaim = val
		}
	}

	// Telemetry - Initialize if env vars are set and struct is nil
	isTelemetryEnvSet := os.Getenv("OPENPONS_TELEMETRY_ENABLED") != "" ||
		os.Getenv("OPENPONS_TELEMETRY_OTLP_ENDPOINT") != ""

	if isTelemetryEnvSet {
		if cfg.Telemetry == nil {
			cfg.Telemetry = &StaticTelemetryConfig{}
		}
	}
	if cfg.Telemetry != nil {
		if val := os.Getenv("OPENPONS_TELEMETRY_ENABLED"); val != "" {
			enabled, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("invalid format for OPENPONS_TELEMETRY_ENABLED '%s': %w", val, err)
			}
			cfg.Telemetry.Enabled = enabled
		}
		if val := os.Getenv("OPENPONS_TELEMETRY_OTLP_ENDPOINT"); val != "" {
			cfg.Telemetry.OTLP.Endpoint = val
		}
	}

	return cfg, nil
}
