package xds

import (
	"fmt"
	"io"
	"log" // Fallback if telemetry.Logger is nil
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/openpons/gateway/internal/telemetry"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// hclogAdapter wraps our Zap logger to be compatible with go-control-plane's hclog interface.
type hclogAdapter struct {
	logger *zap.Logger
	name   string
}

// NewHCLogAdapter creates a new hclogAdapter.
func NewHCLogAdapter(logger *zap.Logger, name string) hclog.Logger {
	if logger == nil {
		// Fallback to standard logger if telemetry.Logger is not initialized
		log.Printf("Warning: telemetry.Logger is nil in NewHCLogAdapter for %s. Falling back to standard log.", name)
		return hclog.New(&hclog.LoggerOptions{
			Name:  name,
			Level: hclog.Info, // Default level
		})
	}
	return &hclogAdapter{
		logger: logger.Named(name), // Add a name to the logger context
		name:   name,
	}
}

func (l *hclogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	fields := l.formatArgs(args...)
	switch level {
	case hclog.Trace, hclog.Debug:
		l.logger.Debug(msg, fields...)
	case hclog.Info:
		l.logger.Info(msg, fields...)
	case hclog.Warn:
		l.logger.Warn(msg, fields...)
	case hclog.Error:
		l.logger.Error(msg, fields...)
	default: // NoLevel, Off
		// Do nothing or log at a default level if appropriate
	}
}

func (l *hclogAdapter) formatArgs(args ...interface{}) []zap.Field {
	if len(args)%2 != 0 {
		// hclog allows a final "error" arg, zap fields are key-value.
		// This is a simplification. A more robust adapter would handle this better.
		return []zap.Field{zap.Any("hclog_args", args)}
	}
	fields := make([]zap.Field, 0, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			key = fmt.Sprintf("arg_%d", i/2) // Fallback key
		}
		fields = append(fields, zap.Any(key, args[i+1]))
	}
	return fields
}

func (l *hclogAdapter) Trace(msg string, args ...interface{}) { l.Log(hclog.Trace, msg, args...) }
func (l *hclogAdapter) Debug(msg string, args ...interface{}) { l.Log(hclog.Debug, msg, args...) }
func (l *hclogAdapter) Info(msg string, args ...interface{})  { l.Log(hclog.Info, msg, args...) }
func (l *hclogAdapter) Warn(msg string, args ...interface{})  { l.Log(hclog.Warn, msg, args...) }
func (l *hclogAdapter) Error(msg string, args ...interface{}) { l.Log(hclog.Error, msg, args...) }

func (l *hclogAdapter) IsTrace() bool { return l.logger.Core().Enabled(zapcore.DebugLevel) } // Zap doesn't have Trace, map to Debug
func (l *hclogAdapter) IsDebug() bool { return l.logger.Core().Enabled(zapcore.DebugLevel) }
func (l *hclogAdapter) IsInfo() bool  { return l.logger.Core().Enabled(zapcore.InfoLevel) }
func (l *hclogAdapter) IsWarn() bool  { return l.logger.Core().Enabled(zapcore.WarnLevel) }
func (l *hclogAdapter) IsError() bool { return l.logger.Core().Enabled(zapcore.ErrorLevel) }

func (l *hclogAdapter) With(args ...interface{}) hclog.Logger {
	fields := l.formatArgs(args...)
	return &hclogAdapter{logger: l.logger.With(fields...), name: l.name}
}
func (l *hclogAdapter) Named(name string) hclog.Logger {
	newName := l.name + "." + name
	if l.name == "" {
		newName = name
	}
	return &hclogAdapter{logger: l.logger.Named(name), name: newName}
}
func (l *hclogAdapter) ResetNamed(name string) hclog.Logger {
	// Zap doesn't have a direct equivalent of resetting name, create new from base.
	// This assumes telemetry.Logger is the base.
	return NewHCLogAdapter(telemetry.Logger, name)
}

// Name returns the name of the logger
func (l *hclogAdapter) Name() string {
	return l.name
}

// StandardWriter returns an io.Writer that can be used for routing standard library messages to this logger
// This method is part of the hclog.Logger interface.
func (l *hclogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer { // Corrected return type to io.Writer
	// hclog provides a default implementation for this if the logger has Emit.
	// However, since we are adapting Zap, we might need a more custom approach
	// or rely on a simpler path if go-control-plane doesn't heavily use this.
	// For now, let's use hclog's internal helper if available, or a basic one.
	// The hclog library itself has `NewStandardWriter` but it's not exported for direct use here.
	// The interface expects this method. A simple implementation:
	if opts == nil {
		opts = &hclog.StandardLoggerOptions{}
	}
	// This is a simplified writer that just calls Log.
	// A full implementation would parse levels from the log line if InferLevels is true.
	return &hclogIOWriter{adapter: l, inferLevels: opts.InferLevels}
}

// hclogIOWriter is a helper to satisfy io.Writer for StandardLogger.
type hclogIOWriter struct {
	adapter     *hclogAdapter
	inferLevels bool
}

func (w *hclogIOWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	level := hclog.Info // Default level
	if w.inferLevels {
		// Basic level inference (can be more sophisticated)
		// This is a very simplified inference.
		smsg := strings.ToLower(msg)
		if strings.Contains(smsg, "error") {
			level = hclog.Error
		} else if strings.Contains(smsg, "warn") || strings.Contains(smsg, "warning") {
			level = hclog.Warn
		} else if strings.Contains(smsg, "debug") {
			level = hclog.Debug
		} else if strings.Contains(smsg, "trace") {
			level = hclog.Trace
		}
	}
	w.adapter.Log(level, msg)
	return len(p), nil
}

func (l *hclogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	if opts == nil {
		opts = &hclog.StandardLoggerOptions{InferLevels: true}
	}
	return log.New(l.StandardWriter(opts), "", 0)
}

// Implement other hclog.Logger methods if necessary (e.g., ImpliedArgs, Name, UpdateLevel, StandardWriter)
// For go-control-plane cache logging, the above should be sufficient.
func (l *hclogAdapter) ImpliedArgs() []interface{} { return nil }

func (l *hclogAdapter) GetLevel() hclog.Level {
	if l.IsError() {
		return hclog.Error
	}
	if l.IsWarn() {
		return hclog.Warn
	}
	if l.IsInfo() {
		return hclog.Info
	}
	if l.IsDebug() {
		return hclog.Debug
	} // Includes Trace
	return hclog.NoLevel
}

// UpdateLevel, StandardWriter, SetLevel are more complex and might not be needed by go-control-plane cache.
func (l *hclogAdapter) SetLevel(level hclog.Level) {} // No-op for simplicity
