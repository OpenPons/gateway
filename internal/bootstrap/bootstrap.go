// Package bootstrap handles the initial startup, configuration loading,
// and wiring of the OpenPons Gateway control plane.
package bootstrap

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time" // For shutdown timeout

	"github.com/openpons/gateway/internal/admin"
	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam"
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/secrets"
	"github.com/openpons/gateway/internal/store"
	"github.com/openpons/gateway/internal/telemetry"
	"github.com/openpons/gateway/internal/xds" // Added
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/openpons/gateway/internal/pluginruntime" // Added
	"github.com/openpons/gateway/internal/proxy"         // Added for proxy routes
	"github.com/openpons/gateway/internal/routing"       // Added for routing.Router
)

// AppConfig holds the application's runtime configuration, loaded initially.
type AppConfig struct {
	ConfigFile      string
	AdminListenAddr string
	XDSListenAddr   string
	LogLevel        string
	DatastoreURL    string // Example: "sqlite:///path/to/openpons.db" or "redis://localhost:6379"
	// Add other initial/bootstrap configurations here
}

var appCfg AppConfig

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "openpons-gateway",
	Short: "OpenPons Gateway Control Plane",
	Long: `OpenPons Gateway is a unified AI gateway to manage, secure, and observe
AI traffic to LLMs, MCP servers, and A2A communication channels.`,
	Run: func(cmd *cobra.Command, args []string) {
		runGateway()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&appCfg.ConfigFile, "config", "", "config file (default is $HOME/.openpons/gateway.yaml or ./config/gateway.yaml)")
	rootCmd.PersistentFlags().StringVar(&appCfg.AdminListenAddr, "admin-addr", ":8080", "Admin API listen address")
	rootCmd.PersistentFlags().StringVar(&appCfg.XDSListenAddr, "xds-addr", ":18000", "xDS server listen address")
	rootCmd.PersistentFlags().StringVar(&appCfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&appCfg.DatastoreURL, "datastore-url", "sqlite://./openpons_data.db", "Datastore connection URL")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// For now, we primarily rely on flags. Config file loading can be added here later.
}

func runGateway() {
	// Initialize logger first
	// Corrected to InitTelemetry, which returns a shutdown function and an error.
	telemetryShutdown, err := telemetry.InitTelemetry(appCfg.LogLevel, "") // Assuming no OTLP endpoint for now, or get from appCfg
	if err != nil {
		log.Fatalf("Failed to initialize telemetry: %v", err)
	}
	defer func() {
		if err := telemetryShutdown(context.Background()); err != nil {
			log.Printf("Error shutting down telemetry: %v", err)
		}
	}()
	logger := telemetry.Logger // Use the global logger initialized by InitTelemetry

	if logger == nil { // Should not happen if InitTelemetry succeeds
		log.Fatal("Telemetry logger initialization failed silently.")
	}

	defer logger.Sync()

	logger.Info("Starting OpenPons Gateway",
		zap.String("admin_addr", appCfg.AdminListenAddr),
		zap.String("xds_addr", appCfg.XDSListenAddr),
		zap.String("log_level", appCfg.LogLevel),
		zap.String("datastore_url", appCfg.DatastoreURL),
	)

	// Initialize datastore connection
	storePollInterval := 10 * time.Second
	s, err := store.NewSQLiteStore(appCfg.DatastoreURL, storePollInterval)
	if err != nil {
		logger.Fatal("Failed to initialize datastore", zap.Error(err))
	}
	// SQLiteStore has a Close method now.
	if s != nil { // Check if store initialization was successful
		defer func() {
			if err := s.Close(); err != nil {
				logger.Error("Failed to close datastore", zap.Error(err))
			}
		}()
	}

	// Initialize and start the ConfigManager
	configManager, err := config.NewConfigManager(appCfg.ConfigFile, s, 1*time.Minute, logger)
	if err != nil {
		logger.Fatal("Failed to initialize config manager", zap.Error(err))
	}
	defer configManager.StopWatching()
	go configManager.StartWatching()

	// Initialize SecretManager (needs to be before IAMService if IAMService uses it for JWT keys)
	encryptionKeyHex := os.Getenv("OPENPONS_SECRETS_ENCRYPTION_KEY_HEX")
	secretManager, err := secrets.NewSecretManager(s, encryptionKeyHex, "local", nil) // Pass the store instance and encryption key
	if err != nil {
		logger.Fatal("Failed to initialize secret manager", zap.Error(err))
	}

	// Initialize IAM Service
	iamService := iam.NewService(s, secretManager, configManager) // Pass secretManager and configManager
	// OIDC config would be loaded from runtime config and applied to iamService if needed.

	// Initialize ProviderRegistry
	// secretManager was already initialized above
	providerRegistry := provider.NewRegistry(secretManager)
	initialRuntimeCfg := configManager.GetCurrentConfig()
	if initialRuntimeCfg != nil && len(initialRuntimeCfg.Providers) > 0 {
		providerRegistry.InitAdapters(initialRuntimeCfg.Providers)
		// InitAdapters does not return an error, logs internally.
	} else {
		logger.Info("No providers defined in initial configuration or config not yet loaded for ProviderRegistry.")
	}

	// Initialize routing.Router
	router := routing.NewRouter(configManager, providerRegistry) // Pass ProviderRegistry

	// Initialize Plugin Runtime (must be done before it's passed to RegisterProxyRoutes)
	var pluginManager pluginruntime.ManagerInterface // Declare as interface type
	initialRuntimeCfgForPlugins := configManager.GetCurrentConfig()
	if initialRuntimeCfgForPlugins != nil && len(initialRuntimeCfgForPlugins.Plugins) > 0 {
		// Pass the configManager to NewPluginManager
		pluginManager, err = pluginruntime.NewPluginManager(initialRuntimeCfgForPlugins.Plugins, configManager)
		if err != nil {
			logger.Fatal("Failed to initialize plugin manager", zap.Error(err))
		}
		// defer pluginManager.Shutdown() // Defer moved to main shutdown sequence
		logger.Info("PluginManager initialized.", zap.Int("plugin_definition_count", len(initialRuntimeCfgForPlugins.Plugins)))
	} else {
		logger.Info("No plugins defined in initial configuration or config not available for plugin manager. PluginManager not started.")
		// Initialize to a nil-safe version if no plugins, so it can be passed without nil pointer issues
		// if RegisterProxyRoutes expects a non-nil pluginManager.
		// However, RegisterProxyRoutes should handle a nil pluginManager gracefully if no plugins are defined.
		// For now, if no plugins, pluginManager will be nil. Handlers should check.
		// A nil pluginManager should be handled gracefully by consumers like RegisterProxyRoutes.
		// If NewPluginManager was called with empty pluginDefs, pluginManager is not nil but will have no plugins.
		// If NewPluginManager returned an error and pluginManager is nil, then it's an issue.
		// The current logic: if err != nil, it fatals. So pluginManager should be non-nil if we reach here.
	}

	// Initialize and start the Admin API server
	// Pass all required dependencies including the new ones for proxy route registration
	adminService := admin.NewService(
		appCfg.AdminListenAddr,
		configManager,
		s,
		secretManager,
		iamService,
		router,           // routing.RouterInterface
		providerRegistry, // provider.RegistryInterface
		pluginManager,    // pluginruntime.ManagerInterface
		logger,           // *zap.Logger
	)

	// Register Proxy Routes on the Admin Server's Mux
	// This was moved from admin.APIServer.registerRoutes to here to ensure all dependencies are available.
	// Alternatively, admin.NewAPIServer could take all these and do it internally.
	// For now, this keeps bootstrap responsible for wiring high-level components.
	if adminMux := adminService.GetRouter(); adminMux != nil {
		proxy.RegisterProxyRoutes(adminMux, configManager, iamService, router, providerRegistry, pluginManager, logger)
		logger.Info("Proxy routes registered on Admin API server's Mux.")
	} else {
		logger.Error("Admin service Mux is not available. Proxy routes cannot be registered.")
		// This would be a critical failure.
	}

	adminService.Start() // Start admin server

	// Initialize and start the xDS server
	defaultNodeID := "openpons_gateway_node" // Define a default node ID for xDS
	xdsServer := xds.NewXDSServer(appCfg.XDSListenAddr, configManager, defaultNodeID)
	// NewXDSServer itself doesn't return an error in the current xds.go, it logs internally.
	// The Start method returns an error.
	go func() {
		// xDS server Start method needs a context.
		// Using context.Background() for now, or could use the main app context `ctx`.
		// If using main app context `ctx`, it would allow graceful shutdown signal to propagate.
		// Let's use a new background context for the xDS server's own lifecycle for now.
		// The xDS server's Stop method is called from its own Start method's goroutine via ctx.Done().
		if err := xdsServer.Start(context.Background()); err != nil {
			logger.Error("xDS server error", zap.Error(err))
		}
	}()

	logger.Info("OpenPons Gateway core services (partially) initialized and starting...")

	// Setup signal handling for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()

	logger.Info("Shutting down OpenPons Gateway...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if adminService != nil {
		if err := adminService.Stop(shutdownCtx); err != nil {
			logger.Error("Admin server shutdown error", zap.Error(err))
		}
	}
	if xdsServer != nil {
		logger.Info("Stopping xDS server...")
		xdsServer.Stop() // Corrected method name
	}
	if pluginManager != nil { // Check if pluginManager was initialized before calling Shutdown
		logger.Info("Stopping PluginManager...")
		pluginManager.Shutdown()
	}
	if providerRegistry != nil {
		providerRegistry.Shutdown()
	}

	logger.Info("OpenPons Gateway shut down gracefully.")
}
