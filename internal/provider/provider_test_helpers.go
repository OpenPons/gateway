package provider

import (
	"context"
	"fmt"
)

// MockSecretRetriever for provider adapter tests
type mockSecretRetriever struct {
	secrets map[string]string
	err     error
}

func (m *mockSecretRetriever) GetSecret(ctx context.Context, id string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	val, ok := m.secrets[id]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", id)
	}
	return val, nil
}

// Add other shared test helpers for the provider package here if needed.
