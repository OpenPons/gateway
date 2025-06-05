package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/openpons/gateway/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStore for secrets tests
type MockStore struct {
	data map[string][]byte
	err  error
}

func NewMockStore() *MockStore {
	return &MockStore{data: make(map[string][]byte)}
}

func (ms *MockStore) Get(ctx context.Context, key string) ([]byte, error) {
	if ms.err != nil {
		return nil, ms.err
	}
	val, ok := ms.data[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return val, nil
}

func (ms *MockStore) Set(ctx context.Context, key string, value []byte) error {
	if ms.err != nil {
		return ms.err
	}
	ms.data[key] = value
	return nil
}

func (ms *MockStore) Delete(ctx context.Context, key string) error {
	if ms.err != nil {
		return ms.err
	}
	delete(ms.data, key)
	return nil
}

func (ms *MockStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	results := make(map[string][]byte)
	for k, v := range ms.data {
		if strings.HasPrefix(k, prefix) {
			results[k] = v
		}
	}
	return results, nil
}
func (ms *MockStore) Watch(ctx context.Context, keyPrefix string) (<-chan store.WatchEvent, error) {
	return nil, fmt.Errorf("watch not implemented in mockstore for secrets")
}
func (ms *MockStore) Close() error { return nil }
func (ms *MockStore) BeginTransaction(ctx context.Context) (store.Transaction, error) {
	return &MockTransaction{store: ms}, nil
}

// MockTransaction for secrets tests
type MockTransaction struct {
	store *MockStore
}

func (mt *MockTransaction) Get(ctx context.Context, key string) ([]byte, error) {
	return mt.store.Get(ctx, key)
}
func (mt *MockTransaction) Set(ctx context.Context, key string, value []byte) error {
	return mt.store.Set(ctx, key, value)
}
func (mt *MockTransaction) Delete(ctx context.Context, key string) error {
	return mt.store.Delete(ctx, key)
}
func (mt *MockTransaction) Commit(ctx context.Context) error   { return nil }
func (mt *MockTransaction) Rollback(ctx context.Context) error { return nil }

// Helper to generate a valid AES-256 key in hex
func generateTestEncryptionKeyHex(t *testing.T) string {
	key := make([]byte, aesKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return hex.EncodeToString(key)
}

func TestNewSecretManager(t *testing.T) {
	mockStore := NewMockStore()

	t.Run("WithValidEncryptionKey", func(t *testing.T) {
		keyHex := generateTestEncryptionKeyHex(t)
		sm, err := NewSecretManager(mockStore, keyHex, "local", nil)
		require.NoError(t, err)
		require.NotNil(t, sm)
		localSM, ok := sm.(*LocalSecretManager)
		require.True(t, ok, "Expected NewSecretManager to return *LocalSecretManager")
		assert.NotNil(t, localSM.encryptionKey)
		assert.Len(t, localSM.encryptionKey, aesKeySize)
	})

	t.Run("WithEmptyEncryptionKey (Plaintext)", func(t *testing.T) {
		sm, err := NewSecretManager(mockStore, "", "local", nil)
		require.NoError(t, err)
		require.NotNil(t, sm)
		localSM, ok := sm.(*LocalSecretManager)
		require.True(t, ok, "Expected NewSecretManager to return *LocalSecretManager")
		assert.Nil(t, localSM.encryptionKey)
	})

	t.Run("WithInvalidEncryptionKeyHex", func(t *testing.T) {
		_, err := NewSecretManager(mockStore, "invalid-hex-key", "local", nil)
		assert.Error(t, err)
	})

	t.Run("WithInvalidEncryptionKeySize", func(t *testing.T) {
		shortKeyHex := hex.EncodeToString([]byte("shortkey"))
		_, err := NewSecretManager(mockStore, shortKeyHex, "local", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid encryption key size")
	})
}

func TestCreateAndGetSecret_Plaintext(t *testing.T) {
	mockStore := NewMockStore()
	sm, err := NewSecretManager(mockStore, "", "local", nil) // No encryption key
	require.NoError(t, err)

	secretName := "test-api-key"
	secretType := "api_key"
	secretValue := "supersecretvalue123"
	providerID := "provider-abc"

	secretID, err := sm.CreateSecret(context.Background(), secretName, secretType, secretValue, providerID)
	require.NoError(t, err)
	require.NotEmpty(t, secretID)

	retrievedValue, err := sm.GetSecret(context.Background(), secretID)
	require.NoError(t, err)
	assert.Equal(t, secretValue, retrievedValue)

	storedData, err := mockStore.Get(context.Background(), "secrets/"+secretID)
	require.NoError(t, err)
	var storedSecret StoredSecret
	err = json.Unmarshal(storedData, &storedSecret)
	require.NoError(t, err)
	assert.Equal(t, secretID, storedSecret.ID)
	assert.Equal(t, secretName, storedSecret.Name)
	assert.Equal(t, secretValue, storedSecret.Value, "Value in store should be plaintext")
}

func TestCreateAndGetSecret_Encrypted(t *testing.T) {
	mockStore := NewMockStore()
	keyHex := generateTestEncryptionKeyHex(t)
	sm, err := NewSecretManager(mockStore, keyHex, "local", nil)
	require.NoError(t, err)

	secretName := "db-password"
	secretType := "database_password"
	secretValue := "very!secure!Pa$$w0rd"
	providerID := "" // No provider

	secretID, err := sm.CreateSecret(context.Background(), secretName, secretType, secretValue, providerID)
	require.NoError(t, err)
	require.NotEmpty(t, secretID)

	retrievedValue, err := sm.GetSecret(context.Background(), secretID)
	require.NoError(t, err)
	assert.Equal(t, secretValue, retrievedValue)

	storedData, err := mockStore.Get(context.Background(), "secrets/"+secretID)
	require.NoError(t, err)
	var storedSecret StoredSecret
	err = json.Unmarshal(storedData, &storedSecret)
	require.NoError(t, err)
	assert.NotEqual(t, secretValue, storedSecret.Value, "Value in store should be encrypted")
	_, err = base64.StdEncoding.DecodeString(storedSecret.Value)
	assert.NoError(t, err, "Stored encrypted value should be base64 encoded")
}

func TestGetSecret_NotFound(t *testing.T) {
	mockStore := NewMockStore()
	sm, _ := NewSecretManager(mockStore, "", "local", nil)
	_, err := sm.GetSecret(context.Background(), "non-existent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStoreSecret_UpdateExisting(t *testing.T) {
	mockStore := NewMockStore()
	keyHex := generateTestEncryptionKeyHex(t)
	sm, err := NewSecretManager(mockStore, keyHex, "local", nil)
	require.NoError(t, err)
	localSM, ok := sm.(*LocalSecretManager)
	require.True(t, ok, "Expected NewSecretManager to return *LocalSecretManager for this test")

	secretName := "updatable-secret"
	secretType := "generic"
	initialValue := "initial_value"
	updatedValue := "updated_value"

	secretID, err := sm.CreateSecret(context.Background(), secretName, secretType, initialValue, "")
	require.NoError(t, err)

	err = sm.StoreSecret(context.Background(), secretID, updatedValue)
	require.NoError(t, err)

	retrievedValue, err := sm.GetSecret(context.Background(), secretID)
	require.NoError(t, err)
	assert.Equal(t, updatedValue, retrievedValue)

	storedData, _ := mockStore.Get(context.Background(), "secrets/"+secretID)
	var storedSecret StoredSecret
	_ = json.Unmarshal(storedData, &storedSecret)
	assert.Equal(t, secretID, storedSecret.ID)
	assert.Equal(t, secretName, storedSecret.Name)

	base64Decoded, _ := base64.StdEncoding.DecodeString(storedSecret.Value)
	decryptedStoredValue, err := localSM.decrypt(base64Decoded) // Use localSM.decrypt
	require.NoError(t, err)
	assert.Equal(t, updatedValue, string(decryptedStoredValue))
	assert.True(t, storedSecret.UpdatedAt.After(storedSecret.CreatedAt))
}

func TestDeleteSecret(t *testing.T) {
	mockStore := NewMockStore()
	sm, _ := NewSecretManager(mockStore, "", "local", nil)

	secretID, err := sm.CreateSecret(context.Background(), "to-delete", "test", "value", "")
	require.NoError(t, err)

	_, err = sm.GetSecret(context.Background(), secretID)
	require.NoError(t, err)

	err = sm.DeleteSecret(context.Background(), secretID)
	require.NoError(t, err)

	_, err = sm.GetSecret(context.Background(), secretID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	err = sm.DeleteSecret(context.Background(), "non-existent-for-delete")
	assert.NoError(t, err)
}

func TestListSecretsMetadata(t *testing.T) {
	mockStore := NewMockStore()
	sm, _ := NewSecretManager(mockStore, "", "local", nil)

	_, err := sm.CreateSecret(context.Background(), "secret-1", "api_key", "val1", "p1")
	require.NoError(t, err)
	_, err = sm.CreateSecret(context.Background(), "secret-2", "generic", "val2", "")
	require.NoError(t, err)
	err = mockStore.Set(context.Background(), "otherdata/somekey", []byte("somedata"))
	require.NoError(t, err)

	metadataList, err := sm.ListSecretsMetadata(context.Background())
	require.NoError(t, err)
	assert.Len(t, metadataList, 2)

	found1 := false
	found2 := false
	for _, meta := range metadataList {
		if meta.Name == "secret-1" {
			assert.Equal(t, "api_key", meta.Type)
			assert.Equal(t, "p1", meta.ProviderID)
			found1 = true
		}
		if meta.Name == "secret-2" {
			assert.Equal(t, "generic", meta.Type)
			assert.Empty(t, meta.ProviderID)
			found2 = true
		}
	}
	assert.True(t, found1, "Metadata for secret-1 not found")
	assert.True(t, found2, "Metadata for secret-2 not found")

	mockStoreEmpty := NewMockStore()
	smEmpty, _ := NewSecretManager(mockStoreEmpty, "", "local", nil)
	metadataListEmpty, err := smEmpty.ListSecretsMetadata(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metadataListEmpty)
}

func TestGetSecret_DecryptionFailure(t *testing.T) {
	mockStore := NewMockStore()
	keyHex1 := generateTestEncryptionKeyHex(t)
	sm1, err := NewSecretManager(mockStore, keyHex1, "local", nil)
	require.NoError(t, err)

	secretValue := "sensitive-data"
	secretID, err := sm1.CreateSecret(context.Background(), "test-decrypt-fail", "test", secretValue, "")
	require.NoError(t, err)

	t.Run("WithDifferentEncryptionKey", func(t *testing.T) {
		keyHex2 := generateTestEncryptionKeyHex(t)
		for keyHex2 == keyHex1 {
			keyHex2 = generateTestEncryptionKeyHex(t)
		}
		sm2, err := NewSecretManager(mockStore, keyHex2, "local", nil)
		require.NoError(t, err)

		_, err = sm2.GetSecret(context.Background(), secretID)
		assert.Error(t, err, "Should fail with different encryption key")
		assert.Contains(t, err.Error(), "failed to decrypt secret", "Error message should indicate decryption failure")
	})

	t.Run("WithCorruptedBase64Data", func(t *testing.T) {
		storedDataBytes, err := mockStore.Get(context.Background(), "secrets/"+secretID)
		require.NoError(t, err)
		var storedSecret StoredSecret
		err = json.Unmarshal(storedDataBytes, &storedSecret)
		require.NoError(t, err)

		corruptedBase64 := storedSecret.Value + "corrupt"
		storedSecret.Value = corruptedBase64
		corruptedDataBytes, _ := json.Marshal(storedSecret)
		err = mockStore.Set(context.Background(), "secrets/"+secretID, corruptedDataBytes)
		require.NoError(t, err)

		_, err = sm1.GetSecret(context.Background(), secretID)
		assert.Error(t, err, "Should fail with corrupted base64 data")
		assert.Contains(t, err.Error(), "failed to base64 decode encrypted secret", "Error message for corrupted base64")
	})

	secretID, err = sm1.CreateSecret(context.Background(), "test-decrypt-fail-2", "test", secretValue, "")
	require.NoError(t, err)

	t.Run("WithCorruptedCiphertext", func(t *testing.T) {
		storedDataBytes, err := mockStore.Get(context.Background(), "secrets/"+secretID)
		require.NoError(t, err)
		var storedSecret StoredSecret
		err = json.Unmarshal(storedDataBytes, &storedSecret)
		require.NoError(t, err)

		encryptedBytes, err := base64.StdEncoding.DecodeString(storedSecret.Value)
		require.NoError(t, err)
		if len(encryptedBytes) > 0 {
			encryptedBytes[len(encryptedBytes)-1] ^= 0xFF
		} else {
			t.Skip("Skipping corrupted ciphertext test as encrypted data is empty")
		}
		corruptedEncryptedValue := base64.StdEncoding.EncodeToString(encryptedBytes)
		storedSecret.Value = corruptedEncryptedValue
		corruptedDataBytes, _ := json.Marshal(storedSecret)
		err = mockStore.Set(context.Background(), "secrets/"+secretID, corruptedDataBytes)
		require.NoError(t, err)

		_, err = sm1.GetSecret(context.Background(), secretID)
		assert.Error(t, err, "Should fail with corrupted ciphertext")
		assert.Contains(t, err.Error(), "failed to decrypt secret", "Error message for corrupted ciphertext")
	})
}
