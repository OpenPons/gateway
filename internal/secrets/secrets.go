// Package secrets provides a placeholder for a secret management service.
// In a real system, this would integrate with Vault, Kubernetes Secrets,
// cloud provider KMS, etc.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64" // For storing encrypted data as string
	"encoding/hex"
	"encoding/json" // Added for marshalling/unmarshalling
	"errors"
	"fmt"
	"io" // For rand.Read
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	vault "github.com/hashicorp/vault/api"
	"github.com/openpons/gateway/internal/store" // Uncommented
)

// SecretManagementService defines the interface for managing secrets.
type SecretManagementService interface {
	GetSecret(ctx context.Context, secretID string) (string, error)
	CreateSecret(ctx context.Context, name, secretType, value, providerID string) (string, error)
	ListSecretsMetadata(ctx context.Context) ([]SecretMetadata, error)
	DeleteSecret(ctx context.Context, secretID string) error
	StoreSecret(ctx context.Context, secretID string, value string) error
}

const (
	// KeySize for AES-256
	aesKeySize = 32
	// NonceSize for AES-GCM
	gcmNonceSize = 12
)

// StoredSecret defines the structure for storing a secret's value and metadata.
// The Value is stored as a string, assuming it's typically text-based (like API keys).
// For binary secrets, []byte and appropriate encoding/decoding would be needed.
type StoredSecret struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`  // e.g., "api_key", "oidc_client_secret", "generic_string"
	Value      string    `json:"value"` // The actual secret value
	ProviderID string    `json:"provider_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"` // For future use, e.g. versioning
}

// LocalSecretManager provides an interface to retrieve secrets using local encryption.
type LocalSecretManager struct {
	store         store.Store // Uncommented and used
	encryptionKey []byte      // Key for AES-GCM encryption
}

// NewLocalSecretManager creates a new LocalSecretManager.
// encryptionKeyHex is the AES-256 key hex-encoded. If empty, encryption is disabled.
func NewLocalSecretManager(s store.Store, encryptionKeyHex string) (*LocalSecretManager, error) {
	var keyBytes []byte
	if encryptionKeyHex != "" {
		decodedKey, err := hex.DecodeString(encryptionKeyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode encryption key from hex: %w", err)
		}
		if len(decodedKey) != aesKeySize {
			return nil, fmt.Errorf("invalid encryption key size: expected %d bytes, got %d", aesKeySize, len(decodedKey))
		}
		keyBytes = decodedKey
		log.Println("SecretManager: Encryption key loaded, secrets will be encrypted.")
	} else {
		log.Println("LocalSecretManager: WARNING - No encryption key provided. Secrets will be stored in plaintext.")
	}
	return &LocalSecretManager{
		store:         s,
		encryptionKey: keyBytes,
	}, nil
}

// NewSecretManager is a factory function that returns an instance of SecretManagementService.
// Currently, it defaults to LocalSecretManager. In the future, it could select
// a manager based on configuration (e.g., Vault, AWS Secrets Manager).
type VaultConfig struct {
	Address string
	Token   string
	Path    string // Base path for secrets in Vault, e.g., "secret/data/openpons"
}

func NewSecretManager(store store.Store, encryptionKeyHex string, managerType string, vaultCfg *VaultConfig) (SecretManagementService, error) {
	switch managerType {
	case "vault":
		if vaultCfg == nil {
			return nil, fmt.Errorf("Vault configuration must be provided for vault secret manager")
		}
		return NewVaultSecretManager(vaultCfg)
	case "local", "": // Default to local
		return NewLocalSecretManager(store, encryptionKeyHex)
	default:
		return nil, fmt.Errorf("unknown secret manager type: %s", managerType)
	}
}

// VaultSecretManager implements SecretManagementService using HashiCorp Vault.
type VaultSecretManager struct {
	client   *vault.Client
	basePath string // e.g., "secret/data/openpons"
}

// NewVaultSecretManager creates a new VaultSecretManager.
func NewVaultSecretManager(cfg *VaultConfig) (*VaultSecretManager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("VaultConfig cannot be nil")
	}

	vaultDefaultConfig := vault.DefaultConfig()
	if cfg.Address != "" {
		vaultDefaultConfig.Address = cfg.Address
	}

	client, err := vault.NewClient(vaultDefaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	} else {
		// Attempt to read token from VAULT_TOKEN env var or ~/.vault-token,
		// which NewClient might do by default if token is not explicitly set.
		// Or, log a warning if no token is found.
		if client.Token() == "" {
			log.Println("VaultSecretManager: WARNING - No Vault token provided in config and not found in standard locations. Operations may fail.")
		}
	}

	basePath := "secret/data/openpons" // Default KV v2 path prefix
	if cfg.Path != "" {
		basePath = cfg.Path
	}

	return &VaultSecretManager{
		client:   client,
		basePath: basePath,
	}, nil
}

// GetSecret retrieves a secret from Vault.
func (vsm *VaultSecretManager) GetSecret(ctx context.Context, secretID string) (string, error) {
	vaultPath := vsm.basePath + "/" + secretID
	log.Printf("VaultSecretManager: Attempting to retrieve secret from Vault path: %s", vaultPath)

	// Using KVv2. Assuming "secret" is the mount path for the KVv2 engine.
	kv := vsm.client.KVv2("secret")
	secret, err := kv.Get(ctx, vaultPath)
	if err != nil {
		// Vault API often returns a detailed error. Check if it's a "not found" type.
		// This can be complex as Vault errors aren't always standard Go errors.
		// A common way is to check the HTTP status code if the error is an `*vault.ResponseError`.
		var respErr *vault.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return "", fmt.Errorf("secret ID '%s' not found in Vault at path %s: %w", secretID, vaultPath, store.ErrNotFound)
		}
		return "", fmt.Errorf("failed to retrieve secret from Vault path %s: %w", vaultPath, err)
	}

	if secret == nil || secret.Data == nil {
		// This case might occur if the path exists but contains no data, or if the response is malformed.
		return "", fmt.Errorf("secret ID '%s' not found in Vault (nil data or secret) at path %s: %w", secretID, vaultPath, store.ErrNotFound)
	}

	// The actual secret data is within secret.Data["data"].(map[string]interface{})
	dataMap, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("failed to parse secret data structure from Vault for ID '%s' at path %s; 'data' field missing or not a map", secretID, vaultPath)
	}

	// Assuming the secret value is stored under the key "value"
	value, ok := dataMap["value"].(string)
	if !ok {
		return "", fmt.Errorf("secret value not found or not a string in Vault data for ID '%s' at path %s (key 'value')", secretID, vaultPath)
	}

	log.Printf("VaultSecretManager: Successfully retrieved secret for ID '%s' from Vault path: %s", secretID, vaultPath)
	return value, nil
}

// CreateSecret creates a secret in Vault.
// It stores the secret value along with its metadata.
func (vsm *VaultSecretManager) CreateSecret(ctx context.Context, name, secretType, value, providerID string) (string, error) {
	secretID := uuid.New().String() // Generate a unique ID for the secret path
	now := time.Now().UTC()

	// Data to be stored in Vault. For KVv2, this map is nested under a "data" key.
	secretData := map[string]interface{}{
		"name":        name,
		"type":        secretType,
		"value":       value, // The actual secret value
		"provider_id": providerID,
		"created_at":  now.Format(time.RFC3339Nano),
		"updated_at":  now.Format(time.RFC3339Nano),
		// We use the Vault path as the ID, so no need to store 'id' field within the secret itself.
	}

	// Path for the secret within the KVv2 engine.
	// vsm.basePath is like "openpons/secrets", so full path becomes "secret/data/openpons/secrets/<secretID>"
	// The client.KVv2("secret") handles the "secret/" part, Put handles "data/" + path.
	// So, the path for Put should be vsm.basePath + "/" + secretID
	vaultPath := vsm.basePath + "/" + secretID

	// Data for KVv2 Put operation must be map[string]interface{}{"data": secretData}
	dataToWrite := map[string]interface{}{
		"data": secretData,
	}

	// Using KVv2. Default mount path for KVv2 is often "secret".
	// If your KV engine is mounted elsewhere, this needs to be configurable.
	// For now, assuming "secret" is the mount path for the KVv2 engine.
	kv := vsm.client.KVv2("secret")
	_, err := kv.Put(ctx, vaultPath, dataToWrite)
	if err != nil {
		return "", fmt.Errorf("failed to write secret to Vault at path %s: %w", vaultPath, err)
	}

	log.Printf("VaultSecretManager: Created secret: Name=%s, Type=%s, ID=%s (Vault Path: %s), ProviderID=%s", name, secretType, secretID, vaultPath, providerID)
	return secretID, nil // Return the generated ID which is part of the path
}

// ListSecretsMetadata lists secrets from Vault. This might be complex depending on how metadata is stored.
func (vsm *VaultSecretManager) ListSecretsMetadata(ctx context.Context) ([]SecretMetadata, error) {
	// Placeholder implementation
	log.Println("VaultSecretManager: ListSecretsMetadata called (placeholder)")
	// Example: vsm.client.KVv2(vsm.mountPath).List(ctx, "") and then Get metadata for each.
	return nil, fmt.Errorf("Vault ListSecretsMetadata not yet implemented")
}

// DeleteSecret deletes a secret from Vault.
// This attempts to permanently delete all versions and metadata of the secret.
func (vsm *VaultSecretManager) DeleteSecret(ctx context.Context, secretID string) error {
	vaultPath := vsm.basePath + "/" + secretID
	log.Printf("VaultSecretManager: Attempting to delete secret from Vault path: %s", vaultPath)

	kv := vsm.client.KVv2("secret")
	err := kv.DeleteMetadata(ctx, vaultPath)
	if err != nil {
		// Check if the error is because the secret was not found.
		// Vault API might return an error that doesn't easily map to store.ErrNotFound.
		// If DeleteMetadata fails because the path doesn't exist, it might still be considered a success for idempotency.
		// However, for clarity, we can log it. A more robust check might involve trying a Get first.
		log.Printf("VaultSecretManager: Failed to delete secret metadata from Vault path %s: %v. This might be a 'not found' error.", vaultPath, err)
		// We could choose to not return an error if it's a "not found" type of error to make deletion idempotent.
		// For now, return the error to indicate the operation might not have performed as expected if the secret didn't exist.
		return fmt.Errorf("failed to delete secret metadata from Vault at path %s: %w", vaultPath, err)
	}

	log.Printf("VaultSecretManager: Successfully deleted secret (all versions and metadata) for ID '%s' from Vault path: %s", secretID, vaultPath)
	return nil
}

// StoreSecret stores/updates a secret in Vault. If the secret exists, its value and updated_at timestamp are updated.
// Other metadata fields (name, type, provider_id, created_at) are preserved if the secret exists.
// If the secret does not exist, it's created with placeholder metadata.
func (vsm *VaultSecretManager) StoreSecret(ctx context.Context, secretID string, value string) error {
	vaultPath := vsm.basePath + "/" + secretID
	now := time.Now().UTC()
	kv := vsm.client.KVv2("secret")

	// Try to get existing secret to preserve metadata
	existingSecretData, err := kv.Get(ctx, vaultPath)
	var dataToStore map[string]interface{}

	if err == nil && existingSecretData != nil && existingSecretData.Data != nil {
		// Secret exists, update it
		currentData, ok := existingSecretData.Data["data"].(map[string]interface{})
		if !ok {
			// Data format is unexpected, overwrite with new structure
			log.Printf("VaultSecretManager: Unexpected data format for existing secret %s at path %s. Overwriting.", secretID, vaultPath)
			dataToStore = map[string]interface{}{
				"value":      value,
				"name":       "Unknown (overwritten)",      // Placeholder
				"type":       "generic (overwritten)",      // Placeholder
				"created_at": now.Format(time.RFC3339Nano), // This effectively resets created_at
				"updated_at": now.Format(time.RFC3339Nano),
			}
		} else {
			// Preserve existing metadata, update value and updated_at
			currentData["value"] = value
			currentData["updated_at"] = now.Format(time.RFC3339Nano)
			// Ensure other essential fields exist if they were somehow missing
			if _, exists := currentData["name"]; !exists {
				currentData["name"] = "Unknown (updated)"
			}
			if _, exists := currentData["type"]; !exists {
				currentData["type"] = "generic (updated)"
			}
			if _, exists := currentData["created_at"]; !exists {
				currentData["created_at"] = now.Format(time.RFC3339Nano) // Set created_at if missing
			}
			dataToStore = currentData
		}
	} else {
		// Secret does not exist or error fetching it (other than NotFound which is handled by err == nil check)
		// Create new secret with placeholder metadata
		log.Printf("VaultSecretManager: Secret %s not found at path %s or error fetching. Creating new.", secretID, vaultPath)
		dataToStore = map[string]interface{}{
			"name":        fmt.Sprintf("Stored Secret %s", secretID),
			"type":        "generic",
			"value":       value,
			"provider_id": "", // No provider ID context here
			"created_at":  now.Format(time.RFC3339Nano),
			"updated_at":  now.Format(time.RFC3339Nano),
		}
	}

	dataToWrite := map[string]interface{}{
		"data": dataToStore,
	}

	_, err = kv.Put(ctx, vaultPath, dataToWrite)
	if err != nil {
		return fmt.Errorf("failed to write secret to Vault at path %s for StoreSecret: %w", vaultPath, err)
	}

	log.Printf("VaultSecretManager: Stored/Updated secret for ID '%s' at Vault path: %s", secretID, vaultPath)
	return nil
}

// encrypt encrypts plaintext using AES-GCM.
// Returns nonce+ciphertext.
func (sm *LocalSecretManager) encrypt(plaintext []byte) ([]byte, error) {
	if len(sm.encryptionKey) == 0 {
		return plaintext, nil // No key, return plaintext
	}
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// decrypt decrypts data (nonce+ciphertext) using AES-GCM.
func (sm *LocalSecretManager) decrypt(data []byte) ([]byte, error) {
	if len(sm.encryptionKey) == 0 {
		return data, nil // No key, return data as is (assumed plaintext)
	}
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// GetSecret retrieves a secret value by its ID.
// In a real implementation, this would fetch from a secure backend.
func (sm *LocalSecretManager) GetSecret(ctx context.Context, secretID string) (string, error) {
	log.Printf("LocalSecretManager: Attempting to retrieve secret for ID '%s'", secretID)

	key := "secrets/" + secretID
	data, err := sm.store.Get(ctx, key)
	if err != nil {
		if err == store.ErrNotFound { // Assuming store returns a specific error for not found
			return "", fmt.Errorf("secret ID '%s' not found: %w", secretID, err)
		}
		return "", fmt.Errorf("failed to retrieve secret '%s' from store: %w", secretID, err)
	}
	if data == nil { // Should be covered by ErrNotFound, but defensive
		return "", fmt.Errorf("secret ID '%s' not found (nil data)", secretID)
	}

	var storedSecret StoredSecret
	if err := json.Unmarshal(data, &storedSecret); err != nil {
		return "", fmt.Errorf("failed to unmarshal secret data for ID '%s': %w", secretID, err)
	}

	// Decryption step
	valueToReturn := storedSecret.Value
	if len(sm.encryptionKey) > 0 {
		encryptedBytes, err := base64.StdEncoding.DecodeString(storedSecret.Value)
		if err != nil {
			// This might happen if the secret was stored plaintext before encryption was enabled
			// or if data is corrupted. For now, assume it might be plaintext if decode fails.
			log.Printf("SecretManager: Failed to base64 decode secret ID '%s', assuming plaintext or corruption: %v", secretID, err)
			// Depending on policy, could return error or the raw value.
			// If we return raw value, it might be misinterpreted by caller if it's actually corrupted ciphertext.
			// Let's be strict: if encryption is on, expect encrypted format.
			return "", fmt.Errorf("failed to base64 decode encrypted secret for ID '%s': %w", secretID, err)
		}
		decryptedBytes, err := sm.decrypt(encryptedBytes)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt secret ID '%s': %w", secretID, err)
		}
		valueToReturn = string(decryptedBytes)
	}

	return valueToReturn, nil
}

// SecretMetadata is for listing secrets without exposing values.
type SecretMetadata struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"` // e.g., "api_key", "generic_string"
	ProviderID string    `json:"provider_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// CreateSecret stores a new secret.
// Returns the ID of the created secret.
func (sm *LocalSecretManager) CreateSecret(ctx context.Context, name, secretType, value, providerID string) (string, error) {
	secretID := "secret-" + uuid.New().String()
	now := time.Now().UTC()

	valueToStore := value
	if len(sm.encryptionKey) > 0 {
		encryptedBytes, err := sm.encrypt([]byte(value))
		if err != nil {
			return "", fmt.Errorf("failed to encrypt secret value for ID %s: %w", secretID, err)
		}
		valueToStore = base64.StdEncoding.EncodeToString(encryptedBytes)
	}

	storedSecret := StoredSecret{
		ID:         secretID,
		Name:       name,
		Type:       secretType,
		Value:      valueToStore,
		ProviderID: providerID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	data, err := json.Marshal(storedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secret for storage (ID: %s): %w", secretID, err)
	}

	key := "secrets/" + secretID
	if err := sm.store.Set(ctx, key, data); err != nil {
		return "", fmt.Errorf("failed to store secret (ID: %s): %w", secretID, err)
	}

	log.Printf("LocalSecretManager: Created secret: Name=%s, Type=%s, ID=%s, ProviderID=%s", name, secretType, secretID, providerID)
	return secretID, nil
}

// ListSecretsMetadata returns metadata for all stored secrets.
// Does NOT return the secret values.
func (sm *LocalSecretManager) ListSecretsMetadata(ctx context.Context) ([]SecretMetadata, error) {
	log.Println("LocalSecretManager: Listing secrets metadata")
	prefix := "secrets/"
	kvPairs, err := sm.store.List(ctx, prefix) // Use List instead of ListKeysByPrefix
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets from store: %w", err)
	}

	var metadataList []SecretMetadata
	for key, data := range kvPairs { // Iterate over map
		if data == nil { // Should not happen if List returns valid pairs
			log.Printf("Nil data for secret key %s during list. Skipping.", key)
			continue
		}

		var storedSecret StoredSecret
		if err := json.Unmarshal(data, &storedSecret); err != nil {
			log.Printf("Error unmarshalling secret data for key %s during list: %v. Skipping.", key, err)
			continue
		}

		// Ensure the ID from the stored secret matches the key's suffix for consistency,
		// though not strictly necessary if keys are always "secrets/{ID}".
		// if storedSecret.ID != strings.TrimPrefix(key, prefix) {
		//  log.Printf("Warning: Mismatch between stored secret ID ('%s') and key ('%s'). Using stored ID.", storedSecret.ID, key)
		// }

		metadataList = append(metadataList, SecretMetadata{
			ID:         storedSecret.ID,
			Name:       storedSecret.Name,
			Type:       storedSecret.Type,
			ProviderID: storedSecret.ProviderID,
			CreatedAt:  storedSecret.CreatedAt,
		})
	}
	log.Printf("LocalSecretManager: Found %d secrets.", len(metadataList))
	return metadataList, nil
}

// DeleteSecret removes a secret by its ID.
func (sm *LocalSecretManager) DeleteSecret(ctx context.Context, secretID string) error {
	log.Printf("LocalSecretManager: Deleting secret: ID=%s", secretID)
	key := "secrets/" + secretID

	// Optional: Check if secret exists before deleting, though Delete should be idempotent.
	// _, err := sm.store.Get(ctx, key)
	// if err != nil {
	// 	if err == store.ErrNotFound {
	// 		return fmt.Errorf("secret ID '%s' not found for deletion: %w", secretID, err)
	// 	}
	// 	return fmt.Errorf("failed to check existence of secret '%s' before deletion: %w", secretID, err)
	// }

	if err := sm.store.Delete(ctx, key); err != nil {
		return fmt.Errorf("failed to delete secret (ID: %s) from store: %w", secretID, err)
	}
	log.Printf("LocalSecretManager: Deleted secret: ID=%s", secretID)
	return nil
}

// StoreSecret stores or updates a secret value by its ID.
// This is a simplified version; a real one might handle versioning or specific update logic.
func (sm *LocalSecretManager) StoreSecret(ctx context.Context, secretID string, value string) error {
	log.Printf("LocalSecretManager: Storing/Updating secret for ID '%s'", secretID)
	key := "secrets/" + secretID

	// For simplicity, we'll assume we're overwriting an existing StoredSecret structure
	// or creating a new one if it doesn't exist.
	// A more robust implementation might fetch existing metadata first.

	valueToStore := value
	if len(sm.encryptionKey) > 0 {
		encryptedBytes, err := sm.encrypt([]byte(value))
		if err != nil {
			return fmt.Errorf("failed to encrypt secret value for ID %s: %w", secretID, err)
		}
		valueToStore = base64.StdEncoding.EncodeToString(encryptedBytes)
	}

	// We need a name and type. If updating, we'd ideally fetch existing.
	// For this interface satisfaction, let's assume a generic type if creating new.
	// This part is tricky without more context on how StoreSecret is used for *new* vs *update*.
	// Let's assume it's primarily for *creating* or *overwriting* where the caller manages metadata.
	// For the purpose of iam.Service using it for JWT key, it's likely creating if not exists.

	// Try to get existing to preserve metadata if updating
	var storedSecret StoredSecret
	now := time.Now().UTC()
	existingData, err := sm.store.Get(ctx, key)
	if err == nil && existingData != nil {
		if errUnmarshal := json.Unmarshal(existingData, &storedSecret); errUnmarshal == nil {
			// Successfully unmarshalled existing, update value and UpdatedAt
			storedSecret.Value = valueToStore
			storedSecret.UpdatedAt = now
		} else {
			// Failed to unmarshal, perhaps create new. This case is problematic.
			// For now, let's assume if it exists, it's valid, or we overwrite with new basic meta.
			log.Printf("LocalSecretManager: Failed to unmarshal existing secret %s, will overwrite with basic metadata: %v", secretID, errUnmarshal)
			storedSecret = StoredSecret{
				ID:        secretID,
				Name:      "Unnamed Secret (Updated)", // Placeholder name
				Type:      "generic_string",           // Placeholder type
				Value:     valueToStore,
				CreatedAt: now, // This might overwrite original CreatedAt if we don't fetch properly
				UpdatedAt: now,
			}
		}
	} else { // Not found or other error, create new
		storedSecret = StoredSecret{
			ID:        secretID,
			Name:      "Unnamed Secret", // Placeholder name
			Type:      "generic_string", // Placeholder type
			Value:     valueToStore,
			CreatedAt: now,
			UpdatedAt: now,
		}
	}

	data, err := json.Marshal(storedSecret)
	if err != nil {
		return fmt.Errorf("failed to marshal secret for storage (ID: %s): %w", secretID, err)
	}

	if err := sm.store.Set(ctx, key, data); err != nil {
		return fmt.Errorf("failed to store secret (ID: %s): %w", secretID, err)
	}
	log.Printf("LocalSecretManager: Stored/Updated secret: ID=%s", secretID)
	return nil
}
