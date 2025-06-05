package plugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	extprocpb "github.com/openpons/gateway/pkg/api/v1alpha1/extproc"
)

// Handshake is a placeholder handshake config for hashicorp go-plugin clients.
var Handshake = plugin.HandshakeConfig{}

// PluginMap is the plugin map used when launching plugins.
var PluginMap = map[string]plugin.Plugin{}

// PluginName is the name used when dispensing the plugin implementation.
const PluginName = "plugin"

// PluginHookService defines the gRPC interface plugins implement.
type PluginHookService interface {
	PreHandleRequest(ctx context.Context) (ProcessingStreamClient, error)
	PostHandleResponse(ctx context.Context) (ProcessingStreamClient, error)
	HealthCheck(ctx context.Context, req *HealthCheckRequest) (*HealthCheckResponse, error)
}

// ProcessingStreamClient represents a bidirectional stream used for plugin hooks.
type ProcessingStreamClient interface {
	Send(*extprocpb.ProcessingRequestChunk) error
	Recv() (*extprocpb.ProcessingResponseChunk, error)
	CloseSend() error
}

// HealthCheckRequest is a minimal health check request.
type HealthCheckRequest struct{}

// HealthCheckResponse represents the plugin health status.
type HealthCheckResponse struct {
	Status string
}
