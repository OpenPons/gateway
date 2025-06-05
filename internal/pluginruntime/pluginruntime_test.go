package pluginruntime

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/pluginruntime/mocks"
	extprocpb "github.com/openpons/gateway/pkg/api/v1alpha1/extproc"
	gwplugin "github.com/openpons/gateway/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/structpb"
)

// Note: The original MockPluginHookService and placeholder types have been removed.
// Accurate testing of gRPC streaming hooks requires proper gRPC client and stream mocks,
// ideally generated using a tool like gomock with protoc-gen-go-grpc.
// The tests below are limited by the inability to fully mock these stream interactions
// without such generated mocks.

func TestNewPluginManager(t *testing.T) {
	pluginDefs := []config.PluginDefinition{
		{ID: "plugin1", Name: "Test Plugin 1", Enabled: true, ExecutablePath: "/bin/true"},
	}
	pm, err := NewPluginManager(pluginDefs, nil) // Pass nil for ConfigManager in this test
	require.NoError(t, err)
	require.NotNil(t, pm)
	assert.Equal(t, pluginDefs, pm.plugins)
	assert.NotNil(t, pm.clients)
}

func TestPluginManager_GetPluginClient_Errors(t *testing.T) {
	defs := []config.PluginDefinition{
		{ID: "p1", Name: "Enabled Plugin", Enabled: true, ExecutablePath: "/bin/true"},
		{ID: "p2", Name: "Disabled Plugin", Enabled: false, ExecutablePath: "/bin/true"},
		{ID: "p3", Name: "No Path Plugin", Enabled: true, ExecutablePath: ""},
	}
	pm, _ := NewPluginManager(defs, nil) // Pass nil for ConfigManager

	tests := []struct {
		name      string
		pluginID  string
		expectErr string
	}{
		{"Plugin not found", "p_nonexistent", "plugin p_nonexistent not found or not enabled"},
		{"Plugin disabled", "p2", "plugin p2 not found or not enabled"},
		{"Plugin no executable path", "p3", "executable path for plugin p3 is not defined"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pm.GetPluginClient(tt.pluginID)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

func TestPluginManager_GetPluginClient_SuccessAndShutdown(t *testing.T) {
	t.Skip("Skipping plugin process test - requires complex build setup and dependencies")
}

func TestPluginManager_ExecuteHooks(t *testing.T) {
	// TODO: Refactor this test suite to use gRPC mocks for PluginHookServiceClient and its stream interfaces.
	// This will involve:
	// 1. Generating mocks using `mockgen` for the interfaces in `pkg/api/v1alpha1/extproc/plugin_hook_service_grpc.pb.go`.
	//    Specifically:
	//    - `PluginHookServiceClient`
	//    - `PluginHookService_PreHandleRequestClient`
	//    - `PluginHookService_PostHandleResponseClient`
	// 2. Modifying `PluginManager.GetPluginClient` or using a test seam to inject the mock `PluginHookServiceClient`.
	// 3. Configuring the mock `PluginHookServiceClient` to return mock stream clients.
	// 4. Configuring mock stream clients (e.g., `MockPluginHookService_PreHandleRequestClient`) to:
	//    - Expect specific `Send()` calls with `*extprocpb.ProcessingRequestChunk`.
	//    - Return specific `*extprocpb.ProcessingResponseChunk` (or `io.EOF`/errors) on `Recv()` calls.
	//    - Expect `CloseSend()` calls.
	// 5. Asserting that `ExecutePreRequestHooks` and `ExecutePostRequestHooks` correctly interact with these mocks,
	//    including data transformation, error handling, and decision-making based on plugin responses.

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a dummy http.Request for tests that need it, at the TestPluginManager_ExecuteHooks scope.
	dummyHTTPRequest, _ := http.NewRequestWithContext(context.Background(), "POST", "/test", nil)
	dummyHTTPRequest.Header = make(http.Header) // Ensure headers map is initialized

	// Common setup for plugin manager with mockable clients
	setupTestPluginManager := func(pluginDefs []config.PluginDefinition) *PluginManager {
		// Create a plugin manager, but we'll override its client retrieval for testing hooks.
		// The ExecutablePath can be dummy for these tests as we won't actually launch plugins.
		pm, err := NewPluginManager(pluginDefs, nil)
		require.NoError(t, err)

		// Initialize testHookClients for injecting mocks.
		pm.testHookClients = make(map[string]gwplugin.PluginHookService)
		for _, pDef := range pluginDefs {
			if pDef.Enabled {
				mockHookClient := mocks.NewMockPluginHookService(ctrl) // Use the correct mock
				pm.testHookClients[pDef.ID] = mockHookClient           // Inject mock gRPC client
			}
		}
		return pm
	}

	t.Run("ExecutePreRequestHooks", func(t *testing.T) {
		t.Run("No plugins configured", func(t *testing.T) {
			pm := setupTestPluginManager([]config.PluginDefinition{})
			route := &config.RouteConfig{Plugins: config.RoutePlugins{Pre: []config.PluginInstanceConfig{}}}
			reqData := "original_request"
			modifiedData, err := pm.ExecutePreRequestHooks(context.Background(), route, dummyHTTPRequest, reqData)
			require.NoError(t, err)
			assert.Equal(t, reqData, modifiedData)
		})

		t.Run("Single plugin modifies request body", func(t *testing.T) {
			pluginID := "p-pre-modify"
			pluginDefs := []config.PluginDefinition{
				{ID: pluginID, Name: "Pre Modify Plugin", Enabled: true, ExecutablePath: "/dummy"},
			}
			pm := setupTestPluginManager(pluginDefs)
			// Retrieve the mock client from pm.testHookClients for setting expectations
			mockClient := pm.testHookClients[pluginID].(*mocks.MockPluginHookService) // Use the correct mock type
			mockStream := mocks.NewMockProcessingStreamClient(ctrl)

			route := &config.RouteConfig{
				Name: "route-pre-modify",
				Plugins: config.RoutePlugins{Pre: []config.PluginInstanceConfig{
					{ID: pluginID, Order: 1, Config: map[string]any{"key": "value"}},
				}},
			}
			originalReqData := "original_request_body"
			modifiedReqData := "modified_request_body_by_plugin"
			expectedPluginConfig, _ := structpb.NewStruct(map[string]any{"key": "value"})

			// Expectations for PreHandleRequest stream
			mockClient.EXPECT().PreHandleRequest(gomock.Any()).Return(mockStream, nil)

			// Expect initial RequestHeaders send
			mockStream.EXPECT().Send(gomock.Cond(func(x any) bool {
				req, ok := x.(*extprocpb.ProcessingRequestChunk)
				if !ok {
					return false
				}
				if req.GetRequestHeaders() == nil {
					return false
				}
				// TODO: Add more specific header checks if necessary
				assert.Equal(t, expectedPluginConfig, req.GetPluginConfig())
				return true
			})).Return(nil)

			// Expect plugin to respond with CONTINUE_PROCESSING for headers
			mockStream.EXPECT().Recv().Return(&extprocpb.ProcessingResponseChunk{
				Action: &extprocpb.ProcessingResponseChunk_CommonResponse{
					CommonResponse: &extprocpb.CommonResponse{Status: extprocpb.CommonResponse_CONTINUE_PROCESSING},
				},
			}, nil)

			// Expect RequestBodyChunk send
			mockStream.EXPECT().Send(gomock.Cond(func(x any) bool {
				req, ok := x.(*extprocpb.ProcessingRequestChunk)
				if !ok {
					return false
				}
				bodyChunk := req.GetRequestBodyChunk()
				if bodyChunk == nil {
					return false
				}
				assert.Equal(t, []byte(originalReqData), bodyChunk.GetBodyChunk().GetChunk())
				assert.True(t, bodyChunk.GetBodyChunk().GetEndOfStream())
				return true
			})).Return(nil)

			// Expect plugin to respond with BodyMutation
			mockStream.EXPECT().Recv().Return(&extprocpb.ProcessingResponseChunk{
				Action: &extprocpb.ProcessingResponseChunk_BodyMutation{
					BodyMutation: &extprocpb.BodyMutation{
						Chunk:       []byte(modifiedReqData),
						EndOfStream: true,
					},
				},
			}, nil)

			// Expect final StreamTrailer send
			mockStream.EXPECT().Send(gomock.Cond(func(x any) bool {
				req, ok := x.(*extprocpb.ProcessingRequestChunk)
				if !ok {
					return false
				}
				return req.GetStreamTrailer() != nil
			})).Return(nil)

			// Expect plugin to respond with CONTINUE_PROCESSING for trailer and then EOF
			mockStream.EXPECT().Recv().Return(&extprocpb.ProcessingResponseChunk{
				Action: &extprocpb.ProcessingResponseChunk_CommonResponse{
					CommonResponse: &extprocpb.CommonResponse{Status: extprocpb.CommonResponse_CONTINUE_PROCESSING},
				},
			}, nil)
			mockStream.EXPECT().Recv().Return(nil, io.EOF)
			mockStream.EXPECT().CloseSend().Return(nil)

			actualModifiedData, err := pm.ExecutePreRequestHooks(context.Background(), route, dummyHTTPRequest, originalReqData)
			require.NoError(t, err)
			assert.Equal(t, modifiedReqData, actualModifiedData)
		})
		// TODO: Add more test cases for PreRequestHooks:
		// - Plugin returns error
		// - Plugin denies request
		// - Plugin sends immediate response
		// - Multiple plugins, correct order, data chaining
		// - Header modification
	})

	t.Run("ExecutePostRequestHooks", func(t *testing.T) {
		t.Run("No plugins configured", func(t *testing.T) {
			pm := setupTestPluginManager([]config.PluginDefinition{})
			route := &config.RouteConfig{Plugins: config.RoutePlugins{Post: []config.PluginInstanceConfig{}}}
			respData := "original_response"
			modifiedData, err := pm.ExecutePostRequestHooks(context.Background(), route, dummyHTTPRequest, respData)
			require.NoError(t, err)
			assert.Equal(t, respData, modifiedData)
		})
		// TODO: Add test cases for PostRequestHooks similar to PreRequestHooks
	})
}
