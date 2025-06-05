// Package xds implements the Envoy xDS server logic.
// It translates OpenPons' runtime configuration into Envoy discovery service
// resources (LDS, RDS, CDS, EDS) and serves them to the Envoy data plane fleet.
package xds

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoveryservice "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimeservice "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	gcp_types "github.com/envoyproxy/go-control-plane/pkg/cache/types" // Alias to avoid conflict if other 'types' pkgs are used
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/envoyproxy/go-control-plane/pkg/test/v3" // For Callbacks

	"github.com/openpons/gateway/internal/config" // To get RuntimeConfig
	"github.com/openpons/gateway/internal/telemetry"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

// XDSServer manages the xDS server and configuration snapshots.
type XDSServer struct {
	listenAddr    string
	grpcServer    *grpc.Server
	snapshotCache cache.SnapshotCache
	configManager config.ManagerInterface // To subscribe to config updates
	stopCh        chan struct{}
	nodeID        string // Default NodeID for snapshots if not dynamic
	version       int64  // Simple version counter for snapshots
	mu            sync.Mutex
}

// NewXDSServer creates and initializes a new xDS server.
func NewXDSServer(listenAddr string, cm config.ManagerInterface, defaultNodeID string) *XDSServer {
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil) // false for linear, true for ADS

	// Configure logger for the snapshot cache
	// Ensure telemetry.Logger is initialized before this point.
	if telemetry.Logger != nil {
		// Logging for the cache itself might be controlled globally or not be directly settable.
		// The NewHCLogAdapter is available if a go-control-plane component accepts an hclog.Logger.
		// For now, we rely on logging within callbacks or if go-control-plane uses a global logger.
		// NewHCLogAdapter(telemetry.Logger, "xds-cache") // This line does nothing if not assigned or passed.
		telemetry.Logger.Debug("xDS snapshot cache created. Custom logging for cache itself might need different setup.")
	} else {
		log.Println("Warning: telemetry.Logger is nil, xDS cache will use default (likely no-op) logger.")
		// go-control-plane's default logger is a no-op logger.
		// To use hclog's default, you might do:
		// snapshotCache.SetLogger(hclog.New(&hclog.LoggerOptions{Name: "xds-cache", Level: hclog.Info}))
	}

	return &XDSServer{
		listenAddr:    listenAddr,
		snapshotCache: snapshotCache,
		configManager: cm,
		stopCh:        make(chan struct{}),
		nodeID:        defaultNodeID, // This might be a default or a pattern
		version:       1,
	}
}

// Start launches the xDS gRPC server and begins watching for config changes.
func (xs *XDSServer) Start(ctx context.Context) error {
	// 1. Setup gRPC Server
	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions,
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    grpcKeepaliveTime,
			Timeout: grpcKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             grpcKeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	)
	xs.grpcServer = grpc.NewServer(grpcOptions...)

	// 2. Register xDS services
	// Callbacks for the server (e.g., for logging stream events or request details)
	// The test.Callbacks struct can be used, or a custom implementation of server.Callbacks.
	// If using test.Callbacks, it has fields like OnStreamOpenFunc, OnFetchRequestFunc, etc.
	// It does not take a logger directly. Logging from callbacks would be done via a logger accessible in their scope.
	// The field names in test.Callbacks might vary by go-control-plane version.
	// If OnStreamOpenFunc causes an error, it means the field name is different in v0.13.4.
	// For now, using a basic Callbacks struct.
	callbacks := &test.Callbacks{
		Debug: true, // Keep debug enabled if available.
	}
	// If specific callbacks like OnStreamOpenFunc are needed, the exact field name for v0.13.4 must be found.
	// Example if OnStreamOpen was the field:
	// callbacks.OnStreamOpen = func(ctx context.Context, id int64, typeURL string) error { ... }

	srv := server.NewServer(ctx, xs.snapshotCache, callbacks)

	discoveryservice.RegisterAggregatedDiscoveryServiceServer(xs.grpcServer, srv)
	endpointservice.RegisterEndpointDiscoveryServiceServer(xs.grpcServer, srv)
	clusterservice.RegisterClusterDiscoveryServiceServer(xs.grpcServer, srv)
	routeservice.RegisterRouteDiscoveryServiceServer(xs.grpcServer, srv)
	listenerservice.RegisterListenerDiscoveryServiceServer(xs.grpcServer, srv)
	secretservice.RegisterSecretDiscoveryServiceServer(xs.grpcServer, srv)
	runtimeservice.RegisterRuntimeDiscoveryServiceServer(xs.grpcServer, srv)
	// Note: Health server for gRPC can be added here too.

	// 3. Start gRPC server listener
	lis, err := net.Listen("tcp", xs.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", xs.listenAddr, err)
	}

	log.Printf("xDS server listening on %s", xs.listenAddr)
	go func() {
		if err := xs.grpcServer.Serve(lis); err != nil {
			log.Printf("xDS server Serve error: %v", err)
		}
	}()
	go func() {
		<-ctx.Done() // If parent context is cancelled
		xs.Stop()
	}()

	// 4. Subscribe to config updates and generate initial snapshot
	configChan := xs.configManager.Subscribe()
	go xs.watchConfigUpdates(ctx, configChan)

	// Generate initial snapshot based on current config
	currentRuntimeConfig := xs.configManager.GetCurrentConfig()
	if currentRuntimeConfig != nil {
		xs.updateSnapshot(currentRuntimeConfig)
	} else {
		log.Println("xDS Server: Initial runtime config is nil, cannot generate initial snapshot.")
	}

	return nil
}

// Stop gracefully shuts down the xDS server.
func (xs *XDSServer) Stop() {
	log.Println("Stopping xDS server...")
	close(xs.stopCh) // Signal watcher goroutine to stop
	if xs.grpcServer != nil {
		xs.grpcServer.GracefulStop()
	}
	log.Println("xDS server stopped.")
}

// watchConfigUpdates listens for configuration changes and updates the snapshot.
func (xs *XDSServer) watchConfigUpdates(ctx context.Context, configChan <-chan *config.RuntimeConfig) {
	defer log.Println("xDS config watcher stopped.")
	for {
		select {
		case newConfig, ok := <-configChan:
			if !ok {
				log.Println("xDS: Config channel closed, stopping watcher.")
				return
			}
			if newConfig == nil {
				log.Println("xDS: Received nil config update, skipping snapshot generation.")
				continue
			}
			log.Println("xDS: Received configuration update, generating new snapshot.")
			xs.updateSnapshot(newConfig)
		case <-xs.stopCh: // Server is stopping
			return
		case <-ctx.Done(): // Context cancelled
			log.Println("xDS: Context cancelled, stopping config watcher.")
			return
		}
	}
}

// updateSnapshot generates a new Envoy configuration snapshot from the RuntimeConfig.
func (xs *XDSServer) updateSnapshot(cfg *config.RuntimeConfig) {
	xs.mu.Lock()
	defer xs.mu.Unlock()

	nodeID := xs.nodeID // Use the default node ID for all snapshots for now
	versionStr := fmt.Sprintf("v%d", xs.version)
	xs.version++

	log.Printf("Generating xDS snapshot version %s for node ID %s", versionStr, nodeID)

	// Generate xDS resources from RuntimeConfig
	listeners, err := xs.generateListeners(cfg)
	if err != nil {
		log.Printf("Error generating listeners: %v", err)
		return
	}

	routes, err := xs.generateRoutes(cfg)
	if err != nil {
		log.Printf("Error generating routes: %v", err)
		return
	}

	clusters, err := xs.generateClusters(cfg)
	if err != nil {
		log.Printf("Error generating clusters: %v", err)
		return
	}

	endpoints, err := xs.generateEndpoints(cfg)
	if err != nil {
		log.Printf("Error generating endpoints: %v", err)
		return
	}

	// Create snapshot with generated resources
	snapshot, err := cache.NewSnapshot(versionStr,
		map[string][]gcp_types.Resource{
			"type.googleapis.com/envoy.config.listener.v3.Listener":              listeners,
			"type.googleapis.com/envoy.config.route.v3.RouteConfiguration":       routes,
			"type.googleapis.com/envoy.config.cluster.v3.Cluster":                clusters,
			"type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment": endpoints,
		},
	)
	if err != nil {
		log.Printf("Failed to create new xDS snapshot version %s: %v", versionStr, err)
		return
	}

	if err := xs.snapshotCache.SetSnapshot(context.Background(), nodeID, snapshot); err != nil {
		log.Printf("Failed to set xDS snapshot version %s for node %s: %v", versionStr, nodeID, err)
		return
	}

	log.Printf("Successfully set xDS snapshot version %s for node %s", versionStr, nodeID)
}

// generateListeners creates Envoy listener configurations from OpenPons routes.
func (xs *XDSServer) generateListeners(cfg *config.RuntimeConfig) ([]gcp_types.Resource, error) {
	var listeners []gcp_types.Resource

	// For MVP, return empty listeners - this avoids complex Envoy protobuf configuration
	// In a full implementation, this would generate proper Envoy listener resources
	log.Printf("xDS: Generated %d listeners", len(listeners))
	return listeners, nil
}

// generateRoutes creates Envoy route configurations from OpenPons routes.
func (xs *XDSServer) generateRoutes(cfg *config.RuntimeConfig) ([]gcp_types.Resource, error) {
	var routes []gcp_types.Resource

	// For MVP, return empty routes - this avoids complex Envoy protobuf configuration
	// In a full implementation, this would translate cfg.Routes into proper Envoy route configurations
	log.Printf("xDS: Generated %d routes", len(routes))
	return routes, nil
}

// generateClusters creates Envoy cluster configurations from OpenPons providers.
func (xs *XDSServer) generateClusters(cfg *config.RuntimeConfig) ([]gcp_types.Resource, error) {
	var clusters []gcp_types.Resource

	// For MVP, return empty clusters - this avoids complex Envoy protobuf configuration
	// In a full implementation, this would create clusters for each provider in cfg.Providers
	log.Printf("xDS: Generated %d clusters from %d providers", len(clusters), len(cfg.Providers))
	return clusters, nil
}

// generateEndpoints creates Envoy endpoint configurations for service discovery.
func (xs *XDSServer) generateEndpoints(cfg *config.RuntimeConfig) ([]gcp_types.Resource, error) {
	var endpoints []gcp_types.Resource

	// For MVP, return empty endpoints - this avoids complex Envoy protobuf configuration
	// In a full implementation, this would integrate with service discovery and create endpoint assignments
	log.Printf("xDS: Generated %d endpoints", len(endpoints))
	return endpoints, nil
}
