package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

// mapProviderErrorToHTTPStatus attempts to map known provider error patterns
// to appropriate HTTP status codes and user-friendly messages.
// This is a basic implementation; more sophisticated error handling and
// structured errors from providers would improve this.
func mapProviderErrorToHTTPStatus(err error, defaultStatusCode int, defaultMessage string) (int, string) {
	if err == nil {
		return defaultStatusCode, defaultMessage // Should not happen if called on an error
	}

	errStr := strings.ToLower(err.Error())

	// Check for common error patterns
	// These are examples and would need to be refined based on actual provider error messages.
	if strings.Contains(errStr, "authentication") || strings.Contains(errStr, "api key") || strings.Contains(errStr, "unauthorized") {
		return http.StatusUnauthorized, "Provider authentication failed. Please check your API key or credentials."
	}
	if strings.Contains(errStr, "rate limit") || strings.Contains(errStr, "quota") {
		return http.StatusTooManyRequests, "Provider rate limit or quota exceeded. Please try again later."
	}
	if strings.Contains(errStr, "invalid request") || strings.Contains(errStr, "bad request") || strings.Contains(errStr, "validation error") || strings.Contains(errStr, "parameter missing") {
		return http.StatusBadRequest, fmt.Sprintf("Invalid request to provider: %s", err.Error())
	}
	if strings.Contains(errStr, "not found") && !strings.Contains(errStr, "route not found") { // Avoid matching our own routing errors
		return http.StatusNotFound, fmt.Sprintf("Resource not found at provider: %s", err.Error())
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "timed out") {
		return http.StatusGatewayTimeout, "Request to provider timed out."
	}
	// Add more specific mappings here based on errors from OpenAI, Anthropic, VertexAI, etc.

	// If no specific mapping, use the provided defaults
	if defaultMessage == "" {
		defaultMessage = fmt.Sprintf("Provider API call failed: %v", err)
	}
	return defaultStatusCode, defaultMessage
}
