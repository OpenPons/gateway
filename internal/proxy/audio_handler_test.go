package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/iam"
	"github.com/openpons/gateway/internal/provider"
	"github.com/openpons/gateway/internal/routing"
	"github.com/openpons/gateway/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Local Mocks for audio_handler_test.go (similar to embedding_handler_test.go)
type MockAudioConfigManager struct {
	GetCurrentConfigFunc func() *config.RuntimeConfig
	SubscribeFunc        func() <-chan *config.RuntimeConfig // Added
}

func (m *MockAudioConfigManager) GetCurrentConfig() *config.RuntimeConfig {
	return m.GetCurrentConfigFunc()
}

// Subscribe provides a dummy implementation for the interface.
func (m *MockAudioConfigManager) Subscribe() <-chan *config.RuntimeConfig {
	if m.SubscribeFunc != nil {
		return m.SubscribeFunc()
	}
	ch := make(chan *config.RuntimeConfig)
	close(ch)
	return ch
}

// Assuming WatchForChanges and LoadInitialConfig are not part of the current ManagerInterface
// func (m *MockAudioConfigManager) WatchForChanges(ctx context.Context, callback func(*config.RuntimeConfig)) {}
// func (m *MockAudioConfigManager) LoadInitialConfig(configPath string) error { return nil }

type MockAudioProviderRegistry struct {
	GetAdapterFunc func(providerID string) (provider.ProviderAdapter, error)
}

func (m *MockAudioProviderRegistry) GetAdapter(providerID string) (provider.ProviderAdapter, error) {
	if m.GetAdapterFunc != nil {
		return m.GetAdapterFunc(providerID)
	}
	return nil, fmt.Errorf("GetAdapterFunc not set on MockAudioProviderRegistry")
}
func (m *MockAudioProviderRegistry) InitializeAdapters(cfg *config.RuntimeConfig, sm provider.SecretRetriever) {
}
func (m *MockAudioProviderRegistry) ShutdownAdapters() {}

// Helper to create a dummy audio file for multipart form tests
func createDummyAudioFile(t *testing.T, content string) (string, func()) {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "testaudio*.mp3")
	require.NoError(t, err)
	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())
	return tmpFile.Name(), func() { os.Remove(tmpFile.Name()) }
}

func TestAudioTranscriptionProxyHandler_ServeHTTP(t *testing.T) {
	telemetry.Logger = zap.NewNop()
	logger := zap.NewNop()

	mockAdapter := &MockProviderAdapter{}
	mockRouter := &MockRouter{}
	mockIAM := &MockIAMService{}
	mockPM := &MockPluginManager{}
	mockCfgMgr := &MockAudioConfigManager{}      // Use local mock type
	mockRegistry := &MockAudioProviderRegistry{} // Use local mock type

	transcriptionHandler := NewAudioTranscriptionProxyHandler(
		mockCfgMgr, mockIAM, mockRouter, mockRegistry, mockPM, logger,
	)

	chiRouter := chi.NewRouter()
	chiRouter.Post("/proxy/models/{modelID}/audio/transcriptions", transcriptionHandler.ServeHTTP)
	testServer := httptest.NewServer(chiRouter)
	defer testServer.Close()

	t.Run("Successful audio transcription", func(t *testing.T) {
		modelID := "whisper-1"
		upstreamModelName := "whisper-1-upstream"
		providerID := "p-audio-trans"
		dummyFilePath, cleanup := createDummyAudioFile(t, "dummy audio data")
		defer cleanup()

		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{
				Models: []config.ModelConfig{
					{ID: modelID, ProviderID: providerID, UpstreamModelName: upstreamModelName},
				},
			}
		}

		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			assert.Equal(t, modelID, reqCtx.ModelID)
			return &routing.ResolvedTarget{
				Adapter: mockAdapter,
				Route:   &config.RouteConfig{ID: "route-audio-trans"},
				Target:  &config.RouteTarget{Ref: modelID},
			}, nil
		}

		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			assert.Equal(t, "test-user-id", principalID)
			// Permission string in AudioTranscriptionProxyHandler is "proxy:invoke:audiotranscription:%s"
			assert.Equal(t, config.Permission(fmt.Sprintf("proxy:invoke:audiotranscription:%s", modelID)), permission)
			return true
		}

		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil
		}
		mockPM.ExecutePostRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, responseBody interface{}) (interface{}, error) {
			return responseBody, nil
		}

		mockAdapter.GetConfigFunc = func() *config.ProviderConfig { // Needed for logging in handler
			return &config.ProviderConfig{ID: providerID}
		}
		mockAdapter.AudioTranscriptionFunc = func(ctx context.Context, request *provider.AudioTranscriptionRequest) (*provider.AudioTranscriptionResponse, error) {
			assert.Equal(t, upstreamModelName, request.Model)
			assert.Equal(t, filepath.Base(dummyFilePath), request.FileName)
			// Check other fields of request if necessary
			return &provider.AudioTranscriptionResponse{Text: "Transcribed audio text"}, nil
		}

		// Create multipart form body
		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("file", filepath.Base(dummyFilePath))
		require.NoError(t, err)
		fileContent, err := os.ReadFile(dummyFilePath)
		require.NoError(t, err)
		_, err = part.Write(fileContent)
		require.NoError(t, err)
		// Add other form fields if needed by the handler or provider adapter
		// e.g., writer.WriteField("model", modelID) // Though handler sets it from path
		require.NoError(t, writer.Close())

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/audio/transcriptions", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var respData provider.AudioTranscriptionResponse
		err = json.NewDecoder(rr.Body).Decode(&respData)
		require.NoError(t, err)
		assert.Equal(t, "Transcribed audio text", respData.Text)
	})

	t.Run("Missing file in multipart form", func(t *testing.T) {
		handler := NewAudioTranscriptionProxyHandler(nil, nil, nil, nil, nil, zap.NewNop())

		chiRouter := chi.NewRouter()
		chiRouter.Post("/proxy/models/{modelID}/audio/transcriptions", handler.ServeHTTP)
		testServer := httptest.NewServer(chiRouter)
		defer testServer.Close()

		modelID := "test-model"

		// Create multipart form without file field
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		// Add a text field instead of file
		writer.WriteField("model", modelID)
		writer.Close()

		urlPath := fmt.Sprintf("%s/proxy/models/%s/audio/transcriptions", testServer.URL, modelID)
		req, _ := http.NewRequest("POST", urlPath, &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid file upload")
	})

	t.Run("Route resolution failure for transcription", func(t *testing.T) {
		modelID := "whisper-route-fail"
		dummyFilePath, cleanup := createDummyAudioFile(t, "dummy audio data")
		defer cleanup()

		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return nil, fmt.Errorf("mock route resolution error")
		}

		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", filepath.Base(dummyFilePath))
		fileContent, _ := os.ReadFile(dummyFilePath)
		part.Write(fileContent)
		writer.Close()

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/audio/transcriptions", testServer.URL, modelID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, body)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "Route not found or routing error")
	})

	t.Run("Adapter AudioTranscription error", func(t *testing.T) {
		modelID := "whisper-adapter-fail"
		upstreamModelName := "whisper-1-af"
		providerID := "p-audio-af"
		dummyFilePath, cleanup := createDummyAudioFile(t, "dummy audio data")
		defer cleanup()

		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{Models: []config.ModelConfig{{ID: modelID, ProviderID: providerID, UpstreamModelName: upstreamModelName}}}
		}
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return &routing.ResolvedTarget{Adapter: mockAdapter, Route: &config.RouteConfig{}, Target: &config.RouteTarget{Ref: modelID}}, nil
		}
		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			return true
		}
		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil
		}
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig { return &config.ProviderConfig{ID: providerID} }
		mockAdapter.AudioTranscriptionFunc = func(ctx context.Context, request *provider.AudioTranscriptionRequest) (*provider.AudioTranscriptionResponse, error) {
			return nil, fmt.Errorf("adapter AudioTranscription error")
		}

		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", filepath.Base(dummyFilePath))
		fileContent, _ := os.ReadFile(dummyFilePath)
		part.Write(fileContent)
		writer.Close()

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/audio/transcriptions", testServer.URL, modelID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, body)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), "Failed to generate transcription")
	})

}

func TestTextToSpeechProxyHandler_ServeHTTP(t *testing.T) {
	telemetry.Logger = zap.NewNop()
	logger := zap.NewNop()

	mockAdapter := &MockProviderAdapter{}
	mockRouter := &MockRouter{}
	mockIAM := &MockIAMService{}
	mockPM := &MockPluginManager{}
	mockCfgMgr := &MockAudioConfigManager{}
	mockRegistry := &MockAudioProviderRegistry{}

	ttsHandler := NewTextToSpeechProxyHandler(
		mockCfgMgr, mockIAM, mockRouter, mockRegistry, mockPM, logger,
	)

	chiRouter := chi.NewRouter()
	chiRouter.Post("/proxy/models/{modelID}/audio/speech", ttsHandler.ServeHTTP)
	testServer := httptest.NewServer(chiRouter)
	defer testServer.Close()

	t.Run("Successful text-to-speech", func(t *testing.T) {
		modelID := "tts-1"
		upstreamModelName := "tts-1-upstream"
		providerID := "p-tts"

		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{
				Models: []config.ModelConfig{
					{ID: modelID, ProviderID: providerID, UpstreamModelName: upstreamModelName},
				},
			}
		}

		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			assert.Equal(t, modelID, reqCtx.ModelID)
			return &routing.ResolvedTarget{
				Adapter: mockAdapter,
				Route:   &config.RouteConfig{ID: "route-tts"},
				Target:  &config.RouteTarget{Ref: modelID},
			}, nil
		}

		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			assert.Equal(t, "test-user-id", principalID)
			// Permission string in TextToSpeechProxyHandler is "proxy:invoke:texttospeech:%s"
			assert.Equal(t, config.Permission(fmt.Sprintf("proxy:invoke:texttospeech:%s", modelID)), permission)
			return true
		}

		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil
		}
		// Post-request hooks for TTS are tricky as it streams directly. Assume no body modification for now.
		mockPM.ExecutePostRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, responseBody interface{}) (interface{}, error) {
			return responseBody, nil
		}

		mockAdapter.GetConfigFunc = func() *config.ProviderConfig {
			return &config.ProviderConfig{ID: providerID}
		}
		mockAdapter.TextToSpeechFunc = func(ctx context.Context, request *provider.TextToSpeechRequest, writer io.Writer) error {
			assert.Equal(t, upstreamModelName, request.Model)
			assert.Equal(t, "Hello world", request.Input)
			assert.Equal(t, "alloy", request.Voice)
			_, err := writer.Write([]byte("dummy speech data"))
			return err
		}

		reqPayload := provider.TextToSpeechRequest{
			Model:          modelID, // User-facing model ID
			Input:          "Hello world",
			Voice:          "alloy",
			ResponseFormat: "mp3",
		}
		reqBodyBytes, _ := json.Marshal(reqPayload)

		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/audio/speech", testServer.URL, modelID)
		req, err := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "audio/mpeg", rr.Header().Get("Content-Type"))
		assert.Equal(t, "dummy speech data", rr.Body.String())
	})

	t.Run("Bad request body for TTS", func(t *testing.T) {
		modelID := "tts-bad-request"
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/audio/speech", testServer.URL, modelID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBufferString("not json"))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid request body")
	})

	t.Run("Route resolution failure for TTS", func(t *testing.T) {
		modelID := "tts-route-fail"
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return nil, fmt.Errorf("tts mock route error")
		}

		reqPayload := provider.TextToSpeechRequest{Model: modelID, Input: "Hello", Voice: "alloy"}
		reqBodyBytes, _ := json.Marshal(reqPayload)
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/audio/speech", testServer.URL, modelID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "Route not found or routing error")
	})

	t.Run("Adapter TextToSpeech error", func(t *testing.T) {
		modelID := "tts-adapter-fail"
		upstreamModelName := "tts-1-af"
		providerID := "p-tts-af"

		mockCfgMgr.GetCurrentConfigFunc = func() *config.RuntimeConfig {
			return &config.RuntimeConfig{Models: []config.ModelConfig{{ID: modelID, ProviderID: providerID, UpstreamModelName: upstreamModelName}}}
		}
		mockRouter.ResolveRouteFunc = func(ctx context.Context, reqCtx routing.IncomingRequestContext) (*routing.ResolvedTarget, error) {
			return &routing.ResolvedTarget{Adapter: mockAdapter, Route: &config.RouteConfig{}, Target: &config.RouteTarget{Ref: modelID}}, nil
		}
		mockIAM.CheckPermissionFunc = func(ctx context.Context, principalID string, authInfo interface{}, permission config.Permission) bool {
			return true
		}
		mockPM.ExecutePreRequestHooksFunc = func(ctx context.Context, route *config.RouteConfig, r *http.Request, requestBody interface{}) (interface{}, error) {
			return requestBody, nil
		}
		mockAdapter.GetConfigFunc = func() *config.ProviderConfig { return &config.ProviderConfig{ID: providerID} }
		mockAdapter.TextToSpeechFunc = func(ctx context.Context, request *provider.TextToSpeechRequest, writer io.Writer) error {
			return fmt.Errorf("adapter TextToSpeech error")
		}

		reqPayload := provider.TextToSpeechRequest{Model: modelID, Input: "Hello", Voice: "alloy"}
		reqBodyBytes, _ := json.Marshal(reqPayload)
		reqCtxWithPrincipal := context.WithValue(context.Background(), iam.ContextKeyPrincipalID, "test-user-id")
		url := fmt.Sprintf("%s/proxy/models/%s/audio/speech", testServer.URL, modelID)
		req, _ := http.NewRequestWithContext(reqCtxWithPrincipal, "POST", url, bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		chiRouter.ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), "Failed to generate speech")
	})
}
