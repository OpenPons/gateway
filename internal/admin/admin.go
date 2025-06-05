// Package admin implements the HTTP handlers for the OpenPons Gateway Admin API.
// It provides CRUD operations for managing gateway resources like providers,
// models, routes, IAM policies, and plugins.
package admin

import (
	"context"
	"log"

	"github.com/go-chi/chi/v5" // Added for GetRouter return type
	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam"
	"github.com/openpons/gateway/internal/pluginruntime"
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/routing"
	"github.com/openpons/gateway/internal/secrets"
	"github.com/openpons/gateway/internal/store"
	"go.uber.org/zap"
)

// Service manages the Admin API server.
type Service struct {
	server *APIServer
	// Dependencies like SecretManager and IAMService are now held by APIServer directly.
	// If Service needed them for other reasons, they would be added here.
}

// NewService creates a new Admin API service.
func NewService(
	listenAddr string,
	cm config.ManagerInterface, // Changed to interface to match APIServer field
	s store.Store,
	sm secrets.SecretManagementService,
	iamSvc iam.ServiceInterface, // Changed to interface to match APIServer field
	routerService routing.RouterInterface,
	providerRegistry provider.RegistryInterface,
	pluginMgr pluginruntime.ManagerInterface,
	logger *zap.Logger,
) *Service {
	// Note: NewAPIServer expects interfaces for cm and iamSvc, which is fine.
	apiServer := NewAPIServer(listenAddr, cm, s, sm, iamSvc, routerService, providerRegistry, pluginMgr, logger)
	return &Service{
		server: apiServer,
	}
}

// Start runs the Admin API HTTP server.
func (s *Service) Start() {
	log.Println("Starting Admin API service...")
	go func() {
		if err := s.server.Start(); err != nil {
			log.Fatalf("Failed to start Admin API server: %v", err)
		}
	}()
}

// Stop gracefully shuts down the Admin API server.
func (s *Service) Stop(ctx context.Context) error {
	log.Println("Admin API service stopping...")
	return s.server.Stop(ctx)
}

// GetRouter returns the Chi router used by the Admin API server.
// This allows other parts of the application (e.g., bootstrap) to register additional routes
// on the same multiplexer if needed (e.g., proxy routes).
func (s *Service) GetRouter() *chi.Mux {
	if s.server == nil {
		return nil // Should not happen if NewService was called
	}
	return s.server.Mux // Assumes APIServer.Mux is public
}
