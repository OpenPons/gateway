package admin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam"           // Added
	"github.com/openpons/gateway/internal/pluginruntime" // Added
	"github.com/openpons/gateway/internal/provider"      // Added
	"github.com/openpons/gateway/internal/proxy"         // Added
	"github.com/openpons/gateway/internal/routing"       // Added
	"github.com/openpons/gateway/internal/secrets"       // Added
	"github.com/openpons/gateway/internal/store"
	"go.uber.org/zap" // Added
)

// APIServer wraps the HTTP server for the Admin API.
type APIServer struct {
	listenAddr       string
	httpServer       *http.Server
	Mux              *chi.Mux                // Changed router to Mux (public)
	configMgr        config.ManagerInterface // Changed to interface
	store            store.Store             // To interact with data
	secretManager    secrets.SecretManagementService
	iamService       iam.ServiceInterface           // Changed to interface
	routerService    routing.RouterInterface        // Added
	providerRegistry provider.RegistryInterface     // Added
	pluginMgr        pluginruntime.ManagerInterface // Added
	logger           *zap.Logger                    // Added
}

// NewAPIServer creates a new Admin APIServer.
func NewAPIServer(
	listenAddr string,
	cm config.ManagerInterface,
	s store.Store,
	sm secrets.SecretManagementService,
	iamSvc iam.ServiceInterface,
	routerSvc routing.RouterInterface,
	registry provider.RegistryInterface,
	pluginMgr pluginruntime.ManagerInterface,
	logger *zap.Logger,
) *APIServer {
	if logger == nil {
		logger = zap.NewNop()
	}
	router := chi.NewRouter()

	// Setup CORS
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"}, // Allow all for now, restrict in prod
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any major browsers
	}))

	// Standard middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger) // Chi's structured logger
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second)) // Set a reasonable timeout

	// Add IAM middleware for authentication and authorization
	if iamSvc != nil { // Only add if IAM service is provided
		// Assuming iamService has a method like AuthMiddleware(requiredPerms ...string) func(next http.Handler) http.Handler
		// For admin routes, we might have a general "admin_access" permission or more granular ones.
		// This is a placeholder for how it might be integrated.
		// router.Use(iamSvc.AuthMiddleware("admin:access")) // Example global auth for all admin routes

		// More typically, auth middleware is applied per-route group or per-route
		// if different permissions are needed. For now, a general placeholder.
		log.Println("AdminAPIServer: IAM Service available, auth middleware would be configured here.")
	} else {
		log.Println("AdminAPIServer: IAM Service not available, running without auth middleware (unsafe for production).")
	}

	api := &APIServer{
		listenAddr:       listenAddr,
		Mux:              router, // Assign to Mux
		configMgr:        cm,
		store:            s,
		secretManager:    sm,
		iamService:       iamSvc,
		routerService:    routerSvc,                    // Added
		providerRegistry: registry,                     // Added
		pluginMgr:        pluginMgr,                    // Added
		logger:           logger.Named("admin-server"), // Added
	}

	// Register routes
	api.registerRoutes()

	api.httpServer = &http.Server{
		Addr:    listenAddr,
		Handler: api.Mux, // Use api.Mux
	}

	return api
}

// Start begins listening for HTTP requests.
func (s *APIServer) Start() error {
	log.Printf("Admin API server listening on %s", s.listenAddr)
	if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("Admin API server ListenAndServe error: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the HTTP server.
func (s *APIServer) Stop(ctx context.Context) error {
	log.Println("Stopping Admin API server...")
	return s.httpServer.Shutdown(ctx)
}

// registerRoutes sets up the API routes and handlers.
func (s *APIServer) registerRoutes() {
	// Type assert interfaces to concrete types expected by NewHandler.
	// This implies that NewAPIServer must be called with concrete types that implement these interfaces.
	configMgrConcrete, okCm := s.configMgr.(*config.ConfigManager)
	if !okCm {
		s.logger.Fatal("APIServer: configMgr is not of concrete type *config.ConfigManager. This is a setup error.")
		// In a real scenario, NewAPIServer should probably return an error if this happens.
	}
	iamServiceConcrete, okIam := s.iamService.(*iam.Service)
	if !okIam {
		s.logger.Fatal("APIServer: iamService is not of concrete type *iam.Service. This is a setup error.")
	}

	// Pass nil for PrometheusClient for now.
	// In a real setup, a Prometheus client instance would be created and passed here,
	// likely configured with the Prometheus server URL from gateway settings.
	h := NewHandler(s.store, configMgrConcrete, s.secretManager, iamServiceConcrete, nil) // Create handler instance

	s.Mux.Route("/v1alpha1", func(r chi.Router) { // Base path for API version, use s.Mux
		// Apply Auth middleware to groups of routes or specific routes
		// Example: r.Group(func(r chi.Router) {
		// 	if s.iamService != nil {
		// 		r.Use(s.iamService.AuthMiddleware("admin:read")) // Example permission for read operations
		// 	}
		// 	r.Get("/providers", h.ListProviders)
		// 	r.Get("/providers/{providerID}", h.GetProvider)
		// 	// ... other GET routes
		// })
		// r.Group(func(r chi.Router) {
		// 	if s.iamService != nil {
		// 		r.Use(s.iamService.AuthMiddleware("admin:write")) // Example permission for write operations
		// 	}
		// 	r.Post("/providers", h.CreateProvider)
		//  // ... other POST, PATCH, DELETE routes
		// })
		// For now, applying placeholder to all admin routes for simplicity of this step.
		// Actual permission mapping would be more granular.
		if s.iamService != nil {
			// Apply a general authentication middleware to all /v1alpha1 routes.
			// This middleware should populate context with principal info.
			r.Use(s.iamService.AuthMiddleware) // Assuming AuthMiddleware is of type func(http.Handler) http.Handler
			log.Println("AdminAPIServer: IAM AuthMiddleware applied to /v1alpha1 routes.")
		}

		// Health & Ready Probes (typically public, no auth)
		// r.Get("/healthz", h.Healthz)
		// r.Get("/readyz", h.ReadyZ)

		// Group all /admin routes and apply authorization
		r.Route("/admin", func(adminRouter chi.Router) {
			if s.iamService != nil {
				// Apply authorization middleware requiring a general admin permission.
				// The AuthzMiddleware should check the principal from context (set by AuthMiddleware).
				adminRouter.Use(s.iamService.AuthzMiddleware(config.Permission("admin:access"))) // Use config.Permission
				log.Println("AdminAPIServer: IAM AuthzMiddleware (admin:access) applied to /admin routes.")
			}

			// Provider routes
			adminRouter.Route("/providers", func(r chi.Router) {
				r.Post("/", h.CreateProvider)
				r.Get("/", h.ListProviders)
				r.Route("/{providerID}", func(r chi.Router) {
					r.Get("/", h.GetProvider)
					r.Patch("/", h.UpdateProvider)
					r.Delete("/", h.DeleteProvider)
					// r.Get("/status", h.GetProviderStatus)
				})
			})

			// Model routes
			adminRouter.Route("/models", func(r chi.Router) {
				r.Post("/", h.CreateModel)
				r.Get("/", h.ListModels)
				r.Route("/{modelID}", func(r chi.Router) {
					r.Get("/", h.GetModel)
					r.Patch("/", h.UpdateModel)
					r.Delete("/", h.DeleteModel) // Placeholder added in handler.go
					// r.Get("/status", h.GetModelStatus)
				})
			})

			// Route configuration routes
			adminRouter.Route("/routes", func(r chi.Router) {
				r.Post("/", h.placeholderHandler) // h.CreateRoute
				r.Get("/", h.placeholderHandler)  // h.ListRoutes
				r.Route("/{routeID}", func(r chi.Router) {
					r.Get("/", h.placeholderHandler)    // h.GetRoute
					r.Patch("/", h.placeholderHandler)  // h.UpdateRoute
					r.Delete("/", h.placeholderHandler) // h.DeleteRoute
				})
			})

			// IAM User routes
			adminRouter.Route("/iam/users", func(r chi.Router) {
				r.Post("/", h.CreateUser)
				r.Get("/", h.ListUsers)
				r.Route("/{userID}", func(r chi.Router) {
					r.Get("/", h.GetUser)
					r.Patch("/", h.UpdateUser)
					r.Delete("/", h.DeleteUser)
					// User API Key routes (nested under user)
					r.Route("/apikeys", func(r chi.Router) {
						r.Post("/", h.CreateUserAPIKey)
						r.Get("/", h.ListUserAPIKeys)
					})
				})
			})

			// IAM APIKey direct management (e.g., delete by key ID)
			adminRouter.Route("/iam/apikeys/{apiKeyID}", func(r chi.Router) {
				r.Delete("/", h.DeleteAPIKey)
				// GET /iam/apikeys/{apiKeyID} is typically not provided for security reasons
			})

			// IAM Group routes
			adminRouter.Route("/iam/groups", func(r chi.Router) {
				r.Post("/", h.CreateGroup)
				r.Get("/", h.ListGroups)
				r.Route("/{groupID}", func(r chi.Router) {
					r.Get("/", h.GetGroup)
					r.Patch("/", h.UpdateGroup)
					r.Delete("/", h.DeleteGroup)
					r.Patch("/members", h.ModifyGroupMembers) // Added route for modifying group members
				})
			})

			// IAM Role routes
			adminRouter.Route("/iam/roles", func(r chi.Router) {
				r.Post("/", h.CreateRole)
				r.Get("/", h.ListRoles)
				r.Route("/{roleName}", func(r chi.Router) {
					r.Get("/", h.GetRole)
					r.Patch("/", h.UpdateRole)
					r.Delete("/", h.DeleteRole)
				})
			})

			// IAM RoleBinding routes
			adminRouter.Route("/iam/rolebindings", func(r chi.Router) {
				r.Post("/", h.CreateRoleBinding)
				r.Get("/", h.ListRoleBindings)
				r.Route("/{bindingID}", func(r chi.Router) {
					r.Get("/", h.GetRoleBinding)
					r.Patch("/", h.UpdateRoleBinding) // Currently returns 405
					r.Delete("/", h.DeleteRoleBinding)
				})
			})

			// IAM ServiceAccount routes
			adminRouter.Route("/iam/serviceaccounts", func(r chi.Router) {
				r.Post("/", h.CreateServiceAccount)
				r.Get("/", h.ListServiceAccounts)
				r.Route("/{serviceAccountID}", func(r chi.Router) {
					r.Get("/", h.GetServiceAccount)
					r.Patch("/", h.UpdateServiceAccount)
					r.Delete("/", h.DeleteServiceAccount)
					// Routes for managing API keys for this specific service account
					r.Route("/apikeys", func(r chi.Router) {
						// Permissions for SA API keys might be same as user API keys or more specific
						// For now, let's assume the same permission as user API keys, or a general admin permission for IAM.
						// The AuthzMiddleware is applied at the /admin level, so specific checks might be in handlers or service.
						r.Post("/", h.CreateServiceAccountAPIKey)
						r.Get("/", h.ListServiceAccountAPIKeys)
						// Individual API key GET/DELETE for a service account's key can use the general
						// /admin/iam/apikeys/{apiKeyID} endpoint, as apiKeyID is globally unique.
					})
				})
			})

			// Secret routes
			adminRouter.Route("/secrets", func(r chi.Router) {
				// Apply more granular permissions if needed, e.g., "admin:secrets:create", "admin:secrets:list", "admin:secrets:delete"
				// For now, relying on the general "admin:access" applied to the "/admin" group.
				r.Post("/", h.CreateSecret)
				r.Get("/", h.ListSecretsMetadata) // Lists metadata, not values
				r.Route("/{secretID}", func(r chi.Router) {
					// GET for a single secret's value is intentionally omitted from admin API for security.
					// If metadata for a single secret is needed, a GetSecretMetadata handler could be added.
					r.Delete("/", h.DeleteSecret)
				})
			})

			// Plugin routes
			adminRouter.Route("/plugins", func(r chi.Router) {
				// Permissions for plugins might be "admin:plugins:list", "admin:plugins:read", "admin:plugins:update"
				// Relying on general "admin:access" for now.
				r.Get("/", h.ListPlugins)
				r.Route("/{pluginID}", func(r chi.Router) {
					r.Get("/", h.GetPlugin)
					r.Patch("/", h.UpdatePlugin) // For enabling/disabling
					r.Get("/configschema", h.GetPluginConfigSchema)
					// TODO: Routes for managing plugin instance configurations if applicable
					// e.g., if a plugin instance (on a route) has specific config that can be updated
					// via admin API, separate from the global PluginDefinition.
					// This is distinct from the PluginDefinition's global 'Enabled' status.
				})
			})

			// Usage routes
			adminRouter.Route("/usage", func(r chi.Router) {
				r.Get("/", h.GetUsage) // GET /admin/usage (summary)
				// Potentially more granular usage endpoints, e.g., /admin/usage/per_model
			})

			// Settings routes
			adminRouter.Route("/settings", func(r chi.Router) {
				r.Get("/", h.GetSettings)      // GET /admin/settings (get all global settings)
				r.Patch("/", h.UpdateSettings) // PATCH /admin/settings (update global settings)
			})
		}) // End of /admin group with Authz

		// Proxy routes
		// These are registered using the proxy.RegisterProxyRoutes function,
		// which sets up the specific handlers from the proxy package.
		// These handlers internally use the iamService.AuthMiddleware.
		proxy.RegisterProxyRoutes(r, s.configMgr, s.iamService, s.routerService, s.providerRegistry, s.pluginMgr, s.logger)
		s.logger.Info("Proxy routes registered via proxy.RegisterProxyRoutes")

		// The placeholder handlers below are now replaced by the call above.
		// r.Route("/proxy/models/{modelID}", func(r chi.Router) {
		// 	r.Post("/embeddings", h.placeholderHandler)
		// 	r.Post("/audio/transcriptions", h.placeholderHandler)
		// 	r.Post("/audio/speech", h.placeholderHandler)
		// })
		// r.Post("/proxy/tools/{toolID}/invoke", h.placeholderHandler)
	})
}
