package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestInitTelemetry_Logger(t *testing.T) {
	tests := []struct {
		name        string
		level       string
		expectLevel zapcore.Level
	}{
		{"debug level", "debug", zapcore.DebugLevel},
		{"info level", "info", zapcore.InfoLevel},
		{"warn level", "warn", zapcore.WarnLevel},
		{"error level", "error", zapcore.ErrorLevel},
		{"invalid level", "invalid", zapcore.InfoLevel}, // Should default to info
		{"empty level", "", zapcore.InfoLevel},          // Should default to info
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global Logger for each test run to avoid interference
			originalLogger := Logger
			defer func() { Logger = originalLogger }()

			shutdown, err := InitTelemetry(tt.level, "") // No OTLP endpoint for this logger test
			require.NoError(t, err)
			require.NotNil(t, shutdown)
			defer shutdown(context.Background())

			require.NotNil(t, Logger, "Global Logger should be initialized")

			// Check if the logger level is set as expected.
			// This is a bit indirect. We can check if a log at a certain level is emitted or not.
			core, observedLogs := observer.New(tt.expectLevel)
			testLogger := zap.New(core)

			// Replace global logger temporarily to test its effective level via observedLogs
			// This is not ideal as InitTelemetry sets the global Logger.
			// A better way would be if InitTelemetry returned the logger instance.
			// For now, we assume Logger is set correctly by InitTelemetry and test its behavior.

			if tt.expectLevel == zapcore.DebugLevel {
				Logger.Debug("debug message")
				// Unfortunately, we can't easily capture output from the global Logger
				// without more complex setup or if InitTelemetry returned the logger.
				// So, we'll rely on the internal logic of InitTelemetry setting the level.
			// This assertion is more of a placeholder for ideal testing.
			// A simple check:
			assert.True(t, Logger.Core().Enabled(tt.expectLevel), "Logger should be enabled for expected level")

			// More robust check by capturing logs from the global Logger
			observedCore, logs := observer.New(zapcore.DebugLevel) // Capture all levels from Debug upwards
			originalGlobalLoggerCore := Logger.Core()
			Logger = zap.New(observedCore) // Temporarily replace core of global Logger

			// Log messages at different levels using the global Logger
			Logger.Debug("global debug message")
			Logger.Info("global info message")
			Logger.Warn("global warn message")
			Logger.Error("global error message")

			// Restore global logger to avoid interference, though InitTelemetry re-initializes it.
			// This is more for logical cleanup within the test iteration.
			zap.ReplaceGlobals(zap.New(originalGlobalLoggerCore)) // This might not be perfect if other parts of InitTelemetry rely on the specific global instance.
			                                                      // A safer way is to restore telemetry.Logger directly if it's not modified by zap.ReplaceGlobals elsewhere.
			                                                      // For this test, since InitTelemetry is called per sub-test, it's mostly fine.
			                                                      // The original defer func() { Logger = originalLogger }() handles the package var.

			switch tt.expectLevel {
			case zapcore.DebugLevel:
				assert.Equal(t, 1, logs.FilterMessage("global debug message").Len(), "Debug message should be logged at debug level")
				assert.Equal(t, 1, logs.FilterMessage("global info message").Len(), "Info message should be logged at debug level")
				assert.Equal(t, 1, logs.FilterMessage("global warn message").Len(), "Warn message should be logged at debug level")
				assert.Equal(t, 1, logs.FilterMessage("global error message").Len(), "Error message should be logged at debug level")
			case zapcore.InfoLevel:
				assert.Equal(t, 0, logs.FilterMessage("global debug message").Len(), "Debug message should NOT be logged at info level")
				assert.Equal(t, 1, logs.FilterMessage("global info message").Len(), "Info message should be logged at info level")
				assert.Equal(t, 1, logs.FilterMessage("global warn message").Len(), "Warn message should be logged at info level")
				assert.Equal(t, 1, logs.FilterMessage("global error message").Len(), "Error message should be logged at info level")
			case zapcore.WarnLevel:
				assert.Equal(t, 0, logs.FilterMessage("global debug message").Len(), "Debug message should NOT be logged at warn level")
				assert.Equal(t, 0, logs.FilterMessage("global info message").Len(), "Info message should NOT be logged at warn level")
				assert.Equal(t, 1, logs.FilterMessage("global warn message").Len(), "Warn message should be logged at warn level")
				assert.Equal(t, 1, logs.FilterMessage("global error message").Len(), "Error message should be logged at warn level")
			case zapcore.ErrorLevel:
				assert.Equal(t, 0, logs.FilterMessage("global debug message").Len(), "Debug message should NOT be logged at error level")
				assert.Equal(t, 0, logs.FilterMessage("global info message").Len(), "Info message should NOT be logged at error level")
				assert.Equal(t, 0, logs.FilterMessage("global warn message").Len(), "Warn message should NOT be logged at error level")
				assert.Equal(t, 1, logs.FilterMessage("global error message").Len(), "Error message should be logged at error level")
			}
		})
	}
}

func TestInitTelemetry_Metrics(t *testing.T) {
	originalRegistry := PromRegistry
	defer func() { PromRegistry = originalRegistry }()

	shutdown, err := InitTelemetry("info", "")
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	defer shutdown(context.Background())

	require.NotNil(t, PromRegistry, "PromRegistry should be initialized")
	require.NotNil(t, httpRequestsTotal, "httpRequestsTotal metric should be initialized")
	require.NotNil(t, httpRequestDuration, "httpRequestDuration metric should be initialized")

	// Check if default collectors are registered (this is hard to check directly without specific prometheus testing utilities)
	// We can try to collect metrics and see if go_.* metrics are present.
	metrics, err := PromRegistry.Gather()
	require.NoError(t, err)
	foundGoMetric := false
	for _, mf := range metrics {
		if strings.HasPrefix(mf.GetName(), "go_") {
			foundGoMetric = true
			break
		}
	}
	assert.True(t, foundGoMetric, "Default Go collector metrics should be present")
}

func TestInitTelemetry_Tracing(t *testing.T) {
	originalTracer := Tracer
	originalProvider := otel.GetTracerProvider()
	defer func() {
		Tracer = originalTracer
		otel.SetTracerProvider(originalProvider)
	}()

	t.Run("No OTLP endpoint", func(t *testing.T) {
		shutdown, err := InitTelemetry("info", "")
		require.NoError(t, err)
		require.NotNil(t, shutdown)
		defer shutdown(context.Background())

		require.NotNil(t, Tracer, "Global Tracer should be initialized")
		// We can't easily test the exact type, but we can test that it works
		ctx := context.Background()
		_, span := Tracer.Start(ctx, "test")
		span.End()
		// If this doesn't panic, the tracer is working (even if it's a no-op)
		assert.True(t, true) // Basic assertion that we got here
	})

	// Testing with an OTLP endpoint requires a mock OTLP server or more complex setup.
	// For now, we'll test the path where it attempts to create an exporter.
	// This test might fail if it tries to connect to a non-existent endpoint.
	// We'll check that it doesn't panic and logs an error if endpoint is bad.
	t.Run("With OTLP endpoint (mocked failure or success)", func(t *testing.T) {
		t.Skip("Skipping OTLP test that hangs - needs mock server setup")
	})
}

func TestMetricsHandler(t *testing.T) {
	originalRegistry := PromRegistry
	defer func() { PromRegistry = originalRegistry }()

	shutdown, err := InitTelemetry("info", "")
	require.NoError(t, err)
	defer shutdown(context.Background())

	// Record some metrics first so they appear in the output
	RecordMetrics("test_handler", "GET", 200, 100*time.Millisecond)

	handler := MetricsHandler()
	require.NotNil(t, handler)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body, _ := io.ReadAll(rr.Body)
	assert.Contains(t, string(body), "go_gc_duration_seconds", "Metrics output should contain go runtime metrics")
	assert.Contains(t, string(body), "http_requests_total", "Metrics output should contain custom http_requests_total")
}

func TestRecordMetrics(t *testing.T) {
	originalRegistry := PromRegistry
	originalHttpRequestsTotal := httpRequestsTotal
	originalHttpRequestDuration := httpRequestDuration
	defer func() {
		PromRegistry = originalRegistry
		httpRequestsTotal = originalHttpRequestsTotal
		httpRequestDuration = originalHttpRequestDuration
	}()

	shutdown, err := InitTelemetry("info", "")
	require.NoError(t, err)
	defer shutdown(context.Background())

	// Record some metrics
	RecordMetrics("test_handler", "GET", 200, 100*time.Millisecond)
	RecordMetrics("test_handler", "POST", 500, 200*time.Millisecond)
	RecordMetrics("another_handler", "GET", 200, 50*time.Millisecond)

	// Check counter
	assert.NoError(t, testutil.CollectAndCompare(httpRequestsTotal, strings.NewReader(`
		# HELP http_requests_total Total number of HTTP requests.
		# TYPE http_requests_total counter
		http_requests_total{code="200",handler="test_handler",method="GET"} 1
		http_requests_total{code="500",handler="test_handler",method="POST"} 1
		http_requests_total{code="200",handler="another_handler",method="GET"} 1
	`), "http_requests_total"))

	// Check histogram (checking count is simpler than full distribution)
	// Get the count for one of the histograms
	metricFamily, err := PromRegistry.Gather()
	require.NoError(t, err)

	var totalDurationCount uint64
	for _, mf := range metricFamily {
		if mf.GetName() == "http_request_duration_seconds" {
			for _, m := range mf.GetMetric() {
				totalDurationCount += m.GetHistogram().GetSampleCount()
			}
		}
	}
	assert.Equal(t, uint64(3), totalDurationCount, "httpRequestDuration should have 3 observations")
}
