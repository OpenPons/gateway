// Package telemetry sets up and manages observability for the OpenPons Gateway.
// This includes structured logging, Prometheus metrics collection,
// and OpenTelemetry tracing.
package telemetry

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0" // Use appropriate version
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	// "google.golang.org/grpc" // For OTLP gRPC exporter
)

var (
	// Logger is the global structured logger.
	Logger *zap.Logger
	// Tracer is the global OpenTelemetry tracer.
	Tracer trace.Tracer
	// Prometheus registry
	PromRegistry *prometheus.Registry

	// Example Prometheus metrics
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
)

const serviceName = "openpons-gateway"

// InitTelemetry initializes logging, metrics, and tracing.
// logLevel: "debug", "info", "warn", "error"
// otlpEndpoint: e.g., "localhost:4317" for gRPC OTLP collector
func InitTelemetry(logLevel string, otlpEndpoint string) (func(context.Context) error, error) {
	// 1. Initialize Structured Logging (Zap)
	var err error
	zapConfig := zap.NewProductionConfig()
	level, err := zapcore.ParseLevel(logLevel)
	if err != nil {
		log.Printf("Invalid log level '%s', defaulting to 'info'", logLevel)
		level = zapcore.InfoLevel
	}
	zapConfig.Level = zap.NewAtomicLevelAt(level)
	zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zapConfig.EncoderConfig.TimeKey = "timestamp"

	Logger, err = zapConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize zap logger: %w", err)
	}
	zap.ReplaceGlobals(Logger) // Replace standard log with Zap
	Logger.Info("Structured logger initialized", zap.String("level", logLevel))

	// 2. Initialize Prometheus Metrics
	PromRegistry = prometheus.NewRegistry()
	PromRegistry.MustRegister(prometheus.NewGoCollector())                                       // Standard Go runtime metrics
	PromRegistry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{})) // Process metrics

	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests.",
		},
		[]string{"code", "method", "handler"}, // labels
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests.",
			Buckets: prometheus.DefBuckets, // Default buckets: .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10
		},
		[]string{"method", "handler"},
	)
	PromRegistry.MustRegister(httpRequestsTotal)
	PromRegistry.MustRegister(httpRequestDuration)
	Logger.Info("Prometheus metrics initialized.")

	// 3. Initialize OpenTelemetry Tracing
	ctx := context.Background()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			// Add other common resource attributes: version, environment, etc.
		),
	)
	if err != nil {
		Logger.Error("Failed to create OpenTelemetry resource", zap.Error(err))
		// Continue without tracing if resource creation fails, or return error
	}

	if otlpEndpoint != "" {
		// Setup OTLP gRPC Exporter
		// Ensure OTLP gRPC collector is running at otlpEndpoint
		// For production, consider secure credentials: grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))
		traceExporter, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithInsecure(), // For local dev; use secure in prod
			otlptracegrpc.WithEndpoint(otlpEndpoint),
			// otlptracegrpc.WithDialOption(grpc.WithBlock()), // Optional: block until connection is up
		)
		if err != nil {
			Logger.Error("Failed to create OTLP trace exporter", zap.Error(err), zap.String("otlp_endpoint", otlpEndpoint))
			// Continue without tracing or return error
		} else {
			// BatchSpanProcessor for better performance
			bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
			tp := sdktrace.NewTracerProvider(
				sdktrace.WithSampler(sdktrace.AlwaysSample()), // Or ParentBased(AlwaysSample())
				sdktrace.WithResource(res),
				sdktrace.WithSpanProcessor(bsp),
			)
			otel.SetTracerProvider(tp)
			otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
			Logger.Info("OpenTelemetry tracing initialized with OTLP exporter", zap.String("endpoint", otlpEndpoint))

			// Set global tracer
			Tracer = otel.Tracer(serviceName)

			// Return shutdown function for the tracer provider
			return tp.Shutdown, nil
		}
	} else {
		Logger.Info("OTLP endpoint not configured; OpenTelemetry tracing will be NOOP.")
		// Set a NOOP tracer provider if no endpoint is configured
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.NeverSample()), // Never sample for NOOP behavior
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(tp)
		Tracer = otel.Tracer(serviceName) // Will be a NOOP tracer due to NeverSample
	}

	// Default shutdown function if OTLP exporter wasn't set up
	return func(context.Context) error { return nil }, nil
}

// MetricsHandler returns an http.Handler for exposing Prometheus metrics.
func MetricsHandler() http.Handler {
	if PromRegistry == nil {
		// Fallback if InitTelemetry wasn't called or failed for Prometheus part
		return promhttp.Handler()
	}
	return promhttp.HandlerFor(PromRegistry, promhttp.HandlerOpts{})
}

// Example of how to use metrics (typically in HTTP middleware or handlers)
func RecordMetrics(handlerName string, method string, code int, duration time.Duration) {
	if httpRequestsTotal != nil {
		httpRequestsTotal.WithLabelValues(fmt.Sprintf("%d", code), method, handlerName).Inc()
	}
	if httpRequestDuration != nil {
		httpRequestDuration.WithLabelValues(method, handlerName).Observe(duration.Seconds())
	}
}

// Middleware for basic request logging and metrics (example for Chi router)
// func TelemetryMiddleware(next http.Handler) http.Handler {
// 	 return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		 start := time.Now()
// 		 ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor) // For Chi to get status code
//
// 		 // OpenTelemetry: Start a new span
// 		 ctx := r.Context()
// 		 if Tracer != nil {
// 			 var span trace.Span
// 			 ctx, span = Tracer.Start(ctx, r.URL.Path, trace.WithSpanKind(trace.SpanKindServer))
// 			 defer span.End()
// 			 // Add attributes to span
// 			 span.SetAttributes(
// 				 semconv.HTTPMethodKey.String(r.Method),
// 				 semconv.HTTPTargetKey.String(r.RequestURI),
// 				 semconv.HTTPRouteKey.String(chi.RouteContext(r.Context()).RoutePattern()), // If using Chi
// 			 )
// 			 r = r.WithContext(ctx) // Propagate context with span
// 		 }
//
// 		 next.ServeHTTP(ww, r)
//
// 		 duration := time.Since(start)
// 		 statusCode := ww.Status()
// 		 routePattern := chi.RouteContext(r.Context()).RoutePattern() // Chi specific
//
// 		 // Zap Logger
// 		 Logger.Info("http_request",
// 			 zap.String("method", r.Method),
// 			 zap.String("path", r.URL.Path),
// 			 zap.String("route", routePattern),
// 			 zap.Int("status_code", statusCode),
// 			 zap.Duration("duration", duration),
// 			 zap.String("remote_addr", r.RemoteAddr),
// 			 zap.String("user_agent", r.UserAgent()),
// 			 zap.String("request_id", middleware.GetReqID(r.Context())), // Chi middleware
// 		 )
//
// 		 // Prometheus Metrics
// 		 RecordMetrics(routePattern, r.Method, statusCode, duration)
//
// 		 // OpenTelemetry: Record status on span
// 		 if Tracer != nil && trace.SpanFromContext(ctx).IsRecording() {
// 			 trace.SpanFromContext(ctx).SetAttributes(semconv.HTTPStatusCodeKey.Int(statusCode))
// 		 }
// 	 })
// }
