package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStore is a mock implementation of store.Store
type MockStore struct {
	data map[string][]byte
	err  error // To simulate store errors
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
		return nil, store.ErrNotFound // Use the actual error from store package
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
	if ms.err != nil {
		return nil, ms.err
	}
	results := make(map[string][]byte)
	for k, v := range ms.data {
		if strings.HasPrefix(k, prefix) {
			results[k] = v
		}
	}
	return results, nil
}

func (ms *MockStore) Watch(ctx context.Context, keyPrefix string) (<-chan store.WatchEvent, error) {
	// Not implemented for these tests, return a closed channel or nil and an error.
	// For simplicity, returning nil and no error, assuming tests won't rely on watch functionality.
	// A more complete mock might return a channel that can be controlled by the test.
	// ch := make(chan store.WatchEvent)
	// close(ch)
	// return ch, nil
	return nil, fmt.Errorf("MockStore.Watch not implemented")
}

func (ms *MockStore) Close() error { return nil }

// BeginTransaction mock implementation
func (ms *MockStore) BeginTransaction(ctx context.Context) (store.Transaction, error) {
	if ms.err != nil {
		return nil, ms.err
	}
	// For simplicity, this mock transaction operates directly on the main MockStore data.
	// A more complex mock might isolate transactional changes.
	return &MockTransaction{store: ms}, nil
}

// MockTransaction is a mock implementation of store.Transaction
type MockTransaction struct {
	store *MockStore // Operates on the parent mock store for simplicity in this example
	// In a real scenario, you might buffer changes here.
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
func (mt *MockTransaction) Commit(ctx context.Context) error {
	return nil /* No-op for this simple mock */
}
func (mt *MockTransaction) Rollback(ctx context.Context) error {
	return nil /* No-op for this simple mock */
}

// MockSecretManager is a mock implementation of iam.SecretManagerInterface (defined in iam.go)
type MockSecretManager struct {
	secrets        map[string]string
	getSecretErr   error // Specific error for GetSecret
	storeSecretErr error // Specific error for StoreSecret
}

func NewMockSecretManager() *MockSecretManager {
	return &MockSecretManager{secrets: make(map[string]string)}
}

func (msm *MockSecretManager) GetSecret(ctx context.Context, id string) (string, error) {
	if msm.getSecretErr != nil {
		return "", msm.getSecretErr
	}
	secret, ok := msm.secrets[id]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", id) // Default not found error
	}
	return secret, nil
}

func (msm *MockSecretManager) StoreSecret(ctx context.Context, id string, value string) error {
	if msm.storeSecretErr != nil {
		return msm.storeSecretErr
	}
	msm.secrets[id] = value
	return nil
}

// MockConfigManager is a mock implementation of iam.ConfigManagerInterface (defined in iam.go)
type MockConfigManager struct {
	cfg *config.RuntimeConfig
}

func NewMockConfigManager(cfg *config.RuntimeConfig) *MockConfigManager {
	return &MockConfigManager{cfg: cfg}
}
func (mcm *MockConfigManager) GetCurrentConfig() *config.RuntimeConfig { return mcm.cfg }
func (mcm *MockConfigManager) Subscribe() <-chan *config.RuntimeConfig {
	ch := make(chan *config.RuntimeConfig, 1)
	if mcm.cfg != nil {
		ch <- mcm.cfg
	}
	return ch
}

// ReloadConfig is a mock implementation for ConfigManagerInterface.
func (mcm *MockConfigManager) ReloadConfig(ctx context.Context) error {
	// This mock implementation can be simple for now.
	// If tests need to assert it's called or simulate errors,
	// it can be expanded (e.g., using testify/mock).
	fmt.Println("MockConfigManager.ReloadConfig called") // Optional: for test debugging
	return nil
}

func setupService(t *testing.T) (*Service, *MockStore, SecretManagerInterface, ConfigManagerInterface) {
	mockStore := NewMockStore()
	mockSecretMgr := NewMockSecretManager() // This now returns the local MockSecretManager which implements iam.SecretManagerInterface
	// Setup a default JWT secret for tests
	err := mockSecretMgr.StoreSecret(context.Background(), gatewayJWTSecretID, "test-jwt-signing-key-32-bytes-long")
	require.NoError(t, err)

	// Setup a default runtime config for ConfigManager
	mockRuntimeCfg := &config.RuntimeConfig{
		IAMConfig: config.IAMConfig{
			Roles: []config.RoleConfig{
				{Name: "admin", Permissions: []config.Permission{"*:*"}},
				{Name: "viewer", Permissions: []config.Permission{"*:read"}},
			},
			// Add other necessary IAM parts if tests depend on them
		},
	}
	mockCfgMgr := NewMockConfigManager(mockRuntimeCfg)

	iamService := NewService(mockStore, mockSecretMgr, mockCfgMgr)
	require.NotNil(t, iamService)
	return iamService, mockStore, mockSecretMgr, mockCfgMgr
}

func TestGenerateAndValidateAPIKey_Valid(t *testing.T) {
	service, _, _, _ := setupService(t)
	userID := "user-123"
	roles := []string{"viewer"}
	keyName := "test-key"

	rawKey, apiKey, err := service.GenerateAPIKey(context.Background(), userID, keyName, roles, time.Time{}) // No expiry
	require.NoError(t, err)
	require.NotEmpty(t, rawKey)
	require.NotNil(t, apiKey)
	assert.Equal(t, userID, apiKey.UserID)
	assert.Equal(t, keyName, apiKey.Name)
	assert.Equal(t, roles, apiKey.RoleNames)
	assert.False(t, apiKey.Revoked)
	assert.True(t, apiKey.ExpiresAt.IsZero())

	validatedKey, err := service.ValidateAPIKey(context.Background(), rawKey)
	require.NoError(t, err)
	require.NotNil(t, validatedKey)
	assert.Equal(t, apiKey.ID, validatedKey.ID)
	assert.Equal(t, userID, validatedKey.UserID)
	assert.False(t, validatedKey.Revoked)
}

func TestValidateAPIKey_InvalidFormat(t *testing.T) {
	service, _, _, _ := setupService(t)
	_, err := service.ValidateAPIKey(context.Background(), "invalid-key-format")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid API key format")
}

func TestValidateAPIKey_NotFound(t *testing.T) {
	service, _, _, _ := setupService(t)
	// Generate a key but don't use the service's store to simulate not found
	randomBytes := make([]byte, apiKeyByteLength)
	_, err := rand.Read(randomBytes)
	require.NoError(t, err)
	nonExistentRawKey := apiKeyPrefix + hex.EncodeToString(randomBytes)

	_, err = service.ValidateAPIKey(context.Background(), nonExistentRawKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key not found")
}

func TestValidateAPIKey_Expired(t *testing.T) {
	service, mockStore, _, _ := setupService(t)
	userID := "user-exp"
	keyName := "expired-key"
	rawKey, generatedKey, err := service.GenerateAPIKey(context.Background(), userID, keyName, []string{"viewer"}, time.Now().UTC().Add(-1*time.Hour)) // Expired 1 hour ago
	require.NoError(t, err)
	require.NotEmpty(t, rawKey)

	// To ensure the test uses the expired key from the store, we can re-fetch it or trust GenerateAPIKey stored it correctly.
	// For robustness, let's ensure the stored key is indeed expired.
	apiKeyData, _ := mockStore.Get(context.Background(), "iam/apikeys/"+generatedKey.ID)
	var storedKey APIKey
	_ = json.Unmarshal(apiKeyData, &storedKey)
	assert.True(t, storedKey.ExpiresAt.Before(time.Now().UTC()))

	_, err = service.ValidateAPIKey(context.Background(), rawKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestValidateAPIKey_Revoked(t *testing.T) {
	service, mockStore, _, _ := setupService(t)
	userID := "user-rev"
	keyName := "revoked-key"

	rawKey, apiKey, err := service.GenerateAPIKey(context.Background(), userID, keyName, []string{"viewer"}, time.Time{})
	require.NoError(t, err)

	// Revoke the key directly in the mock store
	apiKey.Revoked = true
	// apiKey.UpdatedAt = time.Now().UTC() // UpdatedAt does not exist on APIKey struct in types.go
	revokedData, _ := json.Marshal(apiKey)
	err = mockStore.Set(context.Background(), "iam/apikeys/"+apiKey.ID, revokedData)
	require.NoError(t, err)

	_, err = service.ValidateAPIKey(context.Background(), rawKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestMatchPermission(t *testing.T) {
	testCases := []struct {
		name         string
		grantedPerm  config.Permission
		requiredPerm config.Permission
		expected     bool
	}{
		{"exact match", "models:read", "models:read", true},
		{"wildcard action", "models:*", "models:read", true},
		{"wildcard resource", "*:read", "models:read", true},
		{"full wildcard", "*:*", "models:read", true},
		{"full wildcard short", "*", "models:read", true},
		{"no match resource", "routes:read", "models:read", false},
		{"no match action", "models:write", "models:read", false},
		{"granted more specific", "models:read", "models:*", false},          // This is important
		{"required more specific", "models:*", "models:read:specific", true}, // Assuming "models:read:specific" is matched by "models:*"
		{"empty granted", "", "models:read", false},
		{"empty required", "models:read", "", false},
		{"both empty", "", "", true}, // Or false, depending on desired behavior for empty perms
		{"complex resource match", "proxy:invoke:model_xyz", "proxy:invoke:model_xyz", true},
		{"complex resource wildcard action", "proxy:invoke:*", "proxy:invoke:model_xyz", true},
		{"complex resource wildcard resource part", "proxy:*", "proxy:invoke:model_xyz", true}, // This depends on how deep the wildcard goes
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, matchPermission(tc.grantedPerm, tc.requiredPerm))
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	service, _, _, _ := setupService(t)
	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Check context values if needed
		principalID, ok := r.Context().Value(ContextKeyPrincipalID).(string)
		assert.True(t, ok, "PrincipalID should be in context")
		assert.NotEmpty(t, principalID, "PrincipalID should not be empty")
		authMethod, ok := r.Context().Value(ContextKeyAuthMethod).(string)
		assert.True(t, ok, "AuthMethod should be in context")
		assert.NotEmpty(t, authMethod, "AuthMethod should not be empty")
	})

	wrappedHandler := service.AuthMiddleware(testHandler)

	// Case 1: Valid API Key
	userID := "user-auth-api"
	rawAPIKey, _, _ := service.GenerateAPIKey(context.Background(), userID, "auth-api-key", []string{"viewer"}, time.Time{})
	reqAPIKey := httptest.NewRequest("GET", "/", nil)
	reqAPIKey.Header.Set("Authorization", "Bearer "+rawAPIKey)
	rrAPIKey := httptest.NewRecorder()
	handlerCalled = false
	wrappedHandler.ServeHTTP(rrAPIKey, reqAPIKey)
	assert.True(t, handlerCalled, "Handler should be called with valid API key")
	assert.Equal(t, http.StatusOK, rrAPIKey.Code, "Status code should be OK for valid API key")

	// Case 2: Valid JWT
	userIDJWT := "user-auth-jwt"
	jwtToken, _ := service.IssueGatewayJWT(userIDJWT, "auth@example.com", nil)
	reqJWT := httptest.NewRequest("GET", "/", nil)
	reqJWT.Header.Set("Authorization", "Bearer "+jwtToken)
	rrJWT := httptest.NewRecorder()
	handlerCalled = false
	wrappedHandler.ServeHTTP(rrJWT, reqJWT)
	assert.True(t, handlerCalled, "Handler should be called with valid JWT")
	assert.Equal(t, http.StatusOK, rrJWT.Code, "Status code should be OK for valid JWT")

	// Case 3: Invalid API Key
	reqInvalidAPIKey := httptest.NewRequest("GET", "/", nil)
	reqInvalidAPIKey.Header.Set("Authorization", "Bearer "+apiKeyPrefix+"invalidkey")
	rrInvalidAPIKey := httptest.NewRecorder()
	handlerCalled = false
	wrappedHandler.ServeHTTP(rrInvalidAPIKey, reqInvalidAPIKey)
	assert.False(t, handlerCalled, "Handler should NOT be called with invalid API key")
	assert.Equal(t, http.StatusUnauthorized, rrInvalidAPIKey.Code)

	// Case 4: Invalid JWT
	reqInvalidJWT := httptest.NewRequest("GET", "/", nil)
	reqInvalidJWT.Header.Set("Authorization", "Bearer invalidjwttoken")
	rrInvalidJWT := httptest.NewRecorder()
	handlerCalled = false
	wrappedHandler.ServeHTTP(rrInvalidJWT, reqInvalidJWT)
	assert.False(t, handlerCalled, "Handler should NOT be called with invalid JWT")
	assert.Equal(t, http.StatusUnauthorized, rrInvalidJWT.Code)

	// Case 5: No Authorization header (passes through, next handler might deny or allow anonymous)
	reqNoAuth := httptest.NewRequest("GET", "/", nil)
	rrNoAuth := httptest.NewRecorder()
	handlerCalled = false // Reset for this sub-test
	nextHandlerNoAuthCalled := false
	noAuthTestHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerNoAuthCalled = true
		_, principalOK := r.Context().Value(ContextKeyPrincipalID).(string)
		assert.False(t, principalOK, "PrincipalID should NOT be in context for no auth")
	})
	service.AuthMiddleware(noAuthTestHandler).ServeHTTP(rrNoAuth, reqNoAuth)
	assert.True(t, nextHandlerNoAuthCalled, "Handler should be called when no auth header is present")
	assert.Equal(t, http.StatusOK, rrNoAuth.Code) // AuthMiddleware itself doesn't deny if no header
}

func TestAuthzMiddleware(t *testing.T) {
	service, mockStore, _, cfgManager := setupService(t)
	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	requiredPerm := config.Permission("models:read")
	authzWrappedHandler := service.AuthzMiddleware(requiredPerm)(testHandler)

	// To make AuthzMiddleware work, AuthMiddleware must run first to populate context.
	// So we wrap AuthzMiddleware with AuthMiddleware.
	fullAuthPipeline := service.AuthMiddleware(authzWrappedHandler)

	// Case 1: User with sufficient permission via API Key
	userIDWithPerm := "user-authz-perm"
	// Ensure this user has a role that grants "models:read"
	// For this test, let's use the "viewer" role which has "*:read"
	rawAPIKeyPerm, _, _ := service.GenerateAPIKey(context.Background(), userIDWithPerm, "authz-api-key", []string{"viewer"}, time.Time{})
	reqWithPerm := httptest.NewRequest("GET", "/models", nil)
	reqWithPerm.Header.Set("Authorization", "Bearer "+rawAPIKeyPerm)
	rrWithPerm := httptest.NewRecorder()
	handlerCalled = false
	fullAuthPipeline.ServeHTTP(rrWithPerm, reqWithPerm)
	assert.True(t, handlerCalled, "Handler should be called for user with sufficient permission (APIKey)")
	assert.Equal(t, http.StatusOK, rrWithPerm.Code)

	// Case 2: User with insufficient permission via API Key
	userIDNoPerm := "user-authz-noperm"
	// Give a role that doesn't grant "models:read", e.g., a new role or no roles
	// For simplicity, let's assume a key with no roles, and no config bindings for this user.
	rawAPIKeyNoPerm, _, _ := service.GenerateAPIKey(context.Background(), userIDNoPerm, "authz-noperm-api-key", []string{}, time.Time{})
	reqNoPerm := httptest.NewRequest("GET", "/models", nil)
	reqNoPerm.Header.Set("Authorization", "Bearer "+rawAPIKeyNoPerm)
	rrNoPerm := httptest.NewRecorder()
	handlerCalled = false
	fullAuthPipeline.ServeHTTP(rrNoPerm, reqNoPerm)
	assert.False(t, handlerCalled, "Handler should NOT be called for user with insufficient permission (APIKey)")
	assert.Equal(t, http.StatusForbidden, rrNoPerm.Code)

	// Case 3: User with sufficient permission via JWT
	userIDJWTWithPerm := "user-authz-jwt-perm"
	// Ensure this user has a role that grants "models:read"
	// Add a role binding for this user to 'viewer'
	mockCfg := cfgManager.(*MockConfigManager).cfg
	mockCfg.IAMConfig.RoleBindings = append(mockCfg.IAMConfig.RoleBindings, config.RoleBindingConfig{
		PrincipalID: userIDJWTWithPerm, PrincipalType: "user", RoleName: "viewer",
	})
	// Store a dummy UserConfig for this user
	userCfgData, _ := json.Marshal(config.UserConfig{ID: userIDJWTWithPerm, Email: "authz@example.com"})
	_ = mockStore.Set(context.Background(), "iam/users/"+userIDJWTWithPerm, userCfgData)

	jwtWithPerm, _ := service.IssueGatewayJWT(userIDJWTWithPerm, "authz@example.com", nil)
	reqJWTWithPerm := httptest.NewRequest("GET", "/models", nil)
	reqJWTWithPerm.Header.Set("Authorization", "Bearer "+jwtWithPerm)
	rrJWTWithPerm := httptest.NewRecorder()
	handlerCalled = false
	fullAuthPipeline.ServeHTTP(rrJWTWithPerm, reqJWTWithPerm)
	assert.True(t, handlerCalled, "Handler should be called for user with sufficient permission (JWT)")
	assert.Equal(t, http.StatusOK, rrJWTWithPerm.Code)

	// Case 4: No auth info in context (AuthMiddleware didn't run or didn't set principal)
	reqAuthzNoAuthCtx := httptest.NewRequest("GET", "/models", nil)
	rrAuthzNoAuthCtx := httptest.NewRecorder()
	handlerCalled = false
	// Directly call AuthzMiddleware without AuthMiddleware to simulate missing auth context
	service.AuthzMiddleware(requiredPerm)(testHandler).ServeHTTP(rrAuthzNoAuthCtx, reqAuthzNoAuthCtx)
	assert.False(t, handlerCalled, "Handler should NOT be called if auth context is missing")
	assert.Equal(t, http.StatusForbidden, rrAuthzNoAuthCtx.Code, "Should be Forbidden if auth context missing for Authz")
}

func TestProvisionUserFromOIDC(t *testing.T) {
	service, mockStore, _, _ := setupService(t)
	ctx := context.Background()

	emailNew := "newuser@oidc.com"
	nameNew := "New OIDC User"
	oidcGroupsNew := []string{"oidc_group_alpha", "oidc_group_beta"}
	groupMappings := map[string]string{
		"oidc_group_alpha": "internal_group_1",
		"oidc_group_beta":  "internal_group_2",
	}

	// Case 1: New user
	userNew, err := service.ProvisionUserFromOIDC(ctx, emailNew, nameNew, oidcGroupsNew, groupMappings)
	require.NoError(t, err)
	require.NotNil(t, userNew)
	assert.Equal(t, emailNew, userNew.Email)
	assert.Equal(t, "active", userNew.Status)
	assert.Contains(t, userNew.GroupIDs, "internal_group_1")
	assert.Contains(t, userNew.GroupIDs, "internal_group_2")
	assert.Len(t, userNew.GroupIDs, 2)

	// Verify user is in store
	userKey := "iam/users_by_email/" + emailNew
	userIDBytes, err := mockStore.Get(ctx, userKey)
	require.NoError(t, err)
	assert.Equal(t, userNew.ID, string(userIDBytes))

	userDataKey := "iam/users/" + userNew.ID
	userDataBytes, err := mockStore.Get(ctx, userDataKey)
	require.NoError(t, err)
	var storedUserNew config.UserConfig
	err = json.Unmarshal(userDataBytes, &storedUserNew)
	require.NoError(t, err)
	assert.Equal(t, userNew.Email, storedUserNew.Email)

	// Case 2: Existing user, update groups
	emailExisting := "existing@oidc.com"
	nameExisting := "Existing OIDC User"
	userIDExisting := "user-existing-oidc"

	// Pre-populate existing user
	existingUser := config.UserConfig{
		ID:        userIDExisting,
		Email:     emailExisting,
		Status:    "active",
		GroupIDs:  []string{"internal_group_0"}, // Initial group
		CreatedAt: time.Now().UTC().Add(-time.Hour),
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
	}
	existingUserData, _ := json.Marshal(existingUser)
	_ = mockStore.Set(ctx, "iam/users_by_email/"+emailExisting, []byte(userIDExisting))
	_ = mockStore.Set(ctx, "iam/users/"+userIDExisting, existingUserData)

	oidcGroupsUpdate := []string{"oidc_group_beta", "oidc_group_gamma"} // "beta" is existing mapping, "gamma" is new
	groupMappingsUpdate := map[string]string{
		"oidc_group_alpha": "internal_group_1", // Still present but not in oidcGroupsUpdate
		"oidc_group_beta":  "internal_group_2",
		"oidc_group_gamma": "internal_group_3",
	}

	userUpdated, err := service.ProvisionUserFromOIDC(ctx, emailExisting, nameExisting, oidcGroupsUpdate, groupMappingsUpdate)
	require.NoError(t, err)
	require.NotNil(t, userUpdated)
	assert.Equal(t, userIDExisting, userUpdated.ID)
	assert.Contains(t, userUpdated.GroupIDs, "internal_group_2", "Should retain mapped group from new OIDC groups")
	assert.Contains(t, userUpdated.GroupIDs, "internal_group_3", "Should add new mapped group")
	// The current implementation of ProvisionUserFromOIDC re-evaluates all groups based on current OIDC groups and mappings.
	// It does not merge with pre-existing groups that are not part of the current OIDC claims.
	// So, "internal_group_0" will be removed if not re-mapped from oidcGroupsUpdate.
	assert.NotContains(t, userUpdated.GroupIDs, "internal_group_0", "Should not retain old group not in current OIDC claims/mappings")
	assert.NotContains(t, userUpdated.GroupIDs, "internal_group_1", "Should not add group from mapping if OIDC group not present")
	assert.Len(t, userUpdated.GroupIDs, 2, "Should have 2 groups after update") // internal_group_2, internal_group_3
	assert.True(t, userUpdated.UpdatedAt.After(existingUser.UpdatedAt))

	// Case 3: No OIDC groups or no mappings
	emailNoGroups := "nogroups@oidc.com"
	nameNoGroups := "No Groups User"
	userNoGroups, err := service.ProvisionUserFromOIDC(ctx, emailNoGroups, nameNoGroups, []string{}, groupMappings)
	require.NoError(t, err)
	assert.Empty(t, userNoGroups.GroupIDs)

	userNoMappings, err := service.ProvisionUserFromOIDC(ctx, emailNoGroups+"2", nameNoGroups, oidcGroupsNew, map[string]string{})
	require.NoError(t, err)
	assert.Empty(t, userNoMappings.GroupIDs)
}

func TestCheckPermission(t *testing.T) {
	service, mockStore, _, cfgManager := setupService(t)
	ctx := context.Background()

	// Setup users and roles in mock config
	userIDWithRolesInToken := "user-token-roles"
	userIDWithRolesInConfig := "user-config-roles"
	userIDWithNoRoles := "user-no-roles"
	adminRole := "admin"
	viewerRole := "viewer"
	operatorRole := "model_operator" // Defined in loadDefaultRolesAndPermissions

	// Ensure roles are in the service's cache (loaded by loadDefaultRolesAndPermissions)
	// service.roles[adminRole] = config.RoleConfig{Name: adminRole, Permissions: []config.Permission{"*:*"}}
	// service.roles[viewerRole] = config.RoleConfig{Name: viewerRole, Permissions: []config.Permission{"*:read"}}
	// service.roles[operatorRole] = config.RoleConfig{Name: operatorRole, Permissions: []config.Permission{"proxy:invoke:*", "models:read"}}

	// Setup RoleBindings in ConfigManager
	mockCfg := cfgManager.(*MockConfigManager).cfg
	mockCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
		{PrincipalID: userIDWithRolesInConfig, PrincipalType: "user", RoleName: operatorRole},
	}
	// Store a dummy UserConfig for userIDWithRolesInConfig so getResolvedRolesForPrincipal can proceed
	userCfgData, _ := json.Marshal(config.UserConfig{ID: userIDWithRolesInConfig, Email: "config@example.com"})
	_ = mockStore.Set(ctx, "iam/users/"+userIDWithRolesInConfig, userCfgData)

	// Case 1: APIKey with roles
	apiKeyWithRoles := &APIKey{UserID: userIDWithRolesInToken, RoleNames: []string{adminRole}}
	assert.True(t, service.CheckPermission(ctx, userIDWithRolesInToken, apiKeyWithRoles, "models:write"), "APIKey with admin role should have models:write")
	assert.True(t, service.CheckPermission(ctx, userIDWithRolesInToken, apiKeyWithRoles, "*:*"), "APIKey with admin role should have *:*")
	assert.False(t, service.CheckPermission(ctx, userIDWithRolesInToken, &APIKey{UserID: userIDWithRolesInToken, RoleNames: []string{viewerRole}}, "models:write"), "APIKey with viewer role should NOT have models:write")

	// Case 2: JWT with roles in claims
	jwtClaimsWithRoles := &GatewayJWTClaims{UserID: userIDWithRolesInToken, Roles: []string{adminRole}}
	// jwt.RegisteredClaims{Subject: userIDWithRolesInToken} // This line is not needed and causes undefined: jwt if jwt isn't used otherwise in this func
	assert.True(t, service.CheckPermission(ctx, userIDWithRolesInToken, jwtClaimsWithRoles, "routes:delete"), "JWT with admin role in claims should have routes:delete")

	// Case 3: No roles in authInfo, roles resolved from ConfigManager (RoleBindings)
	// APIKey with no direct roles, user has 'operatorRole' via config binding
	apiKeyNoRoles := &APIKey{UserID: userIDWithRolesInConfig, RoleNames: []string{}}
	assert.True(t, service.CheckPermission(ctx, userIDWithRolesInConfig, apiKeyNoRoles, "models:read"), "User with operator role from config should have models:read via APIKey")
	assert.True(t, service.CheckPermission(ctx, userIDWithRolesInConfig, apiKeyNoRoles, "proxy:invoke:some_model"), "User with operator role from config should have proxy:invoke via APIKey")
	assert.False(t, service.CheckPermission(ctx, userIDWithRolesInConfig, apiKeyNoRoles, "admin:manage_users"), "User with operator role from config should NOT have admin:manage_users via APIKey")

	// JWT with no direct roles, user has 'operatorRole' via config binding
	jwtClaimsNoRoles := &GatewayJWTClaims{UserID: userIDWithRolesInConfig, Roles: []string{}}
	// jwt.RegisteredClaims{Subject: userIDWithRolesInConfig} // This line is not needed
	assert.True(t, service.CheckPermission(ctx, userIDWithRolesInConfig, jwtClaimsNoRoles, "providers:read"), "User with operator role from config should have providers:read via JWT")

	// Case 4: No roles in authInfo, no roles in ConfigManager for the user
	apiKeyUserNoRoles := &APIKey{UserID: userIDWithNoRoles, RoleNames: []string{}}
	assert.False(t, service.CheckPermission(ctx, userIDWithNoRoles, apiKeyUserNoRoles, "models:read"), "User with no roles should NOT have models:read")

	jwtClaimsUserNoRoles := &GatewayJWTClaims{UserID: userIDWithNoRoles, Roles: []string{}}
	// jwt.RegisteredClaims{Subject: userIDWithNoRoles} // This line is not needed
	assert.False(t, service.CheckPermission(ctx, userIDWithNoRoles, jwtClaimsUserNoRoles, "*:*"), "User with no roles should NOT have *:*")

	// Case 5: Principal has a role that doesn't exist in the service's role cache
	apiKeyWithUnknownRole := &APIKey{UserID: "user-unknown-role", RoleNames: []string{"non_existent_role"}}
	assert.False(t, service.CheckPermission(ctx, "user-unknown-role", apiKeyWithUnknownRole, "models:read"), "User with non-existent role should not have permission")

	// Case 6: Permission matching variations (already covered by TestMatchPermission, but good to have an integration point)
	// User has "proxy:invoke:*" via operatorRole binding
	assert.True(t, service.CheckPermission(ctx, userIDWithRolesInConfig, apiKeyNoRoles, "proxy:invoke:specific_model_id"), "proxy:invoke:* should grant proxy:invoke:specific_model_id")

	// Case 7: User permissions via group membership
	groupViewerID := "group-viewer-test"
	userInGroupViewer := "user-in-group-viewer"

	// Add group and user to store
	groupCfgData, _ := json.Marshal(config.GroupConfig{ID: groupViewerID, Name: "Test Viewer Group"})
	_ = mockStore.Set(ctx, "iam/groups/"+groupViewerID, groupCfgData)

	userInGroupCfg := config.UserConfig{ID: userInGroupViewer, Email: "groupuser@example.com", GroupIDs: []string{groupViewerID}}
	userInGroupData, _ := json.Marshal(userInGroupCfg)
	_ = mockStore.Set(ctx, "iam/users/"+userInGroupViewer, userInGroupData)

	// Add RoleBinding for the group
	originalBindings := mockCfg.IAMConfig.RoleBindings
	mockCfg.IAMConfig.RoleBindings = append(mockCfg.IAMConfig.RoleBindings, config.RoleBindingConfig{
		PrincipalID: groupViewerID, PrincipalType: "group", RoleName: viewerRole,
	})
	// Force re-evaluation of roles by clearing and re-subscribing or by creating a new service instance for this sub-test if needed.
	// For simplicity here, we assume the config change is picked up or that getResolvedRolesForPrincipal reads fresh config.
	// In a real scenario with dynamic config, this might need more setup.

	apiKeyUserInGroup := &APIKey{UserID: userInGroupViewer, RoleNames: []string{}} // No roles in token
	assert.True(t, service.CheckPermission(ctx, userInGroupViewer, apiKeyUserInGroup, "models:read"), "User in viewer group should have models:read")
	assert.False(t, service.CheckPermission(ctx, userInGroupViewer, apiKeyUserInGroup, "models:write"), "User in viewer group should NOT have models:write")

	jwtUserInGroup := &GatewayJWTClaims{UserID: userInGroupViewer, Roles: []string{}} // No roles in token
	assert.True(t, service.CheckPermission(ctx, userInGroupViewer, jwtUserInGroup, "routes:read"), "User in viewer group (JWT) should have routes:read")
	assert.False(t, service.CheckPermission(ctx, userInGroupViewer, jwtUserInGroup, "routes:write"), "User in viewer group (JWT) should NOT have routes:write")

	// Restore original bindings for other tests if necessary, or ensure tests are isolated.
	mockCfg.IAMConfig.RoleBindings = originalBindings
}

func TestJWTGenerationAndValidation(t *testing.T) {
	service, mockStoreFromSetup, _, cfgManager := setupService(t) // Get the mockStore from setup
	userID := "user-jwt-test"
	email := "jwt@example.com"
	oidcGroups := []string{"group1", "group2"}

	// Mock roles in config for role resolution during JWT issuance
	// Get the mock config manager and update its underlying config
	// This cast is safe because setupService returns our MockConfigManager.
	currentMockCfgManager := cfgManager.(*MockConfigManager)
	if currentMockCfgManager.cfg == nil {
		currentMockCfgManager.cfg = &config.RuntimeConfig{}
	}
	if currentMockCfgManager.cfg.IAMConfig.RoleBindings == nil {
		currentMockCfgManager.cfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{}
	}
	currentMockCfgManager.cfg.IAMConfig.RoleBindings = append(currentMockCfgManager.cfg.IAMConfig.RoleBindings, config.RoleBindingConfig{
		PrincipalID:   userID,
		PrincipalType: "user",
		RoleName:      "viewer", // Ensure "viewer" role is defined in mockRuntimeCfg.IAMConfig.Roles in setupService
	})
	// Also ensure the user "user-jwt-test" exists in the store so getResolvedRolesForPrincipal can find it.
	userForJWT := config.UserConfig{ID: userID, Email: email, Status: "active", CreatedAt: time.Now()}
	userForJWTData, err := json.Marshal(userForJWT)
	require.NoError(t, err)
	err = mockStoreFromSetup.Set(context.Background(), "iam/users/"+userID, userForJWTData)
	require.NoError(t, err)
	// Store email index as well, as ProvisionUserFromOIDC would do
	err = mockStoreFromSetup.Set(context.Background(), "iam/users_by_email/"+email, []byte(userID))
	require.NoError(t, err)

	tokenString, err := service.IssueGatewayJWT(userID, email, oidcGroups)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	claims, err := service.ValidateGatewayJWT(tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, oidcGroups, claims.Groups)
	assert.Equal(t, "openpons-gateway", claims.Issuer)
	assert.Equal(t, userID, claims.Subject)
	// Check if "viewer" role is present (based on mock setup or direct binding)
	// This depends on how getResolvedRolesForPrincipal works with the mock config.
	// The current mock setup for roles in setupService is static.
	// If roles are dynamically added to mockRuntimeCfg.IAMConfig.Roles, ensure they are used.
	// The test for getResolvedRolesForPrincipal would be more direct for that.
	// Here, we check if *any* roles were resolved, or a specific one if we ensure its setup.
	// Based on current setup, default roles are loaded, but not necessarily bound to "user-jwt-test"
	// unless RoleBindings are added to the mockRuntimeCfg.
	// The IssueGatewayJWT will try to resolve roles. If none, it might assign a default or empty.
	// Let's assume for this test, we expect at least the roles resolved by getResolvedRolesForPrincipal.
	// The current getResolvedRolesForPrincipal will use the RoleBindings from mockRuntimeCfg.
	assert.Contains(t, claims.Roles, "viewer", "JWT claims should contain resolved roles")

	// Test with an invalid token
	_, err = service.ValidateGatewayJWT(tokenString + "invalid")
	assert.Error(t, err)

	// Test with an expired token (requires manipulating time or token generation)
	// This is more complex to test without time manipulation libraries or internal access.
	// For now, we'll skip direct expiry testing here but ensure basic validation works.

	// Test with a different signing key (simulated by changing service.jwtKey temporarily, if possible, or using a new service instance)
	serviceWithDifferentKey, _, _, _ := setupService(t)
	serviceWithDifferentKey.jwtKey = []byte("another-signing-key-that-is-32-bytes")
	_, err = serviceWithDifferentKey.ValidateGatewayJWT(tokenString)
	assert.Error(t, err, "Token validated with a different key should fail")

}

func TestNewService_JWTKeyLoad_Success(t *testing.T) {
	mockStore := NewMockStore()
	mockSecretMgr := NewMockSecretManager()
	mockCfgMgr := NewMockConfigManager(&config.RuntimeConfig{}) // Minimal config

	validKey := "a-valid-jwt-signing-key-that-is-32-bytes-long"
	err := mockSecretMgr.StoreSecret(context.Background(), gatewayJWTSecretID, validKey)
	require.NoError(t, err)

	service := NewService(mockStore, mockSecretMgr, mockCfgMgr)
	require.NotNil(t, service)
	assert.Equal(t, []byte(validKey), service.jwtKey, "Service should use the JWT key from secret manager")
}

func TestNewService_JWTKeyLoad_SecretManagerError(t *testing.T) {
	mockStore := NewMockStore()
	mockSecretMgr := NewMockSecretManager()
	mockCfgMgr := NewMockConfigManager(&config.RuntimeConfig{})

	// Simulate GetSecret returning an error
	mockSecretMgr.getSecretErr = fmt.Errorf("failed to connect to secret store")

	service := NewService(mockStore, mockSecretMgr, mockCfgMgr)
	require.NotNil(t, service)
	// Expect fallback key to be used
	assert.Equal(t, []byte("fallback-insecure-key-please-configure-secret"), service.jwtKey, "Service should use fallback key on secret manager error")
	// TODO: Add log capture to verify warning message
}

func TestNewService_JWTKeyLoad_EmptySecret(t *testing.T) {
	mockStore := NewMockStore()
	mockSecretMgr := NewMockSecretManager()
	mockCfgMgr := NewMockConfigManager(&config.RuntimeConfig{})

	// Simulate GetSecret returning an empty key (but no error)
	// Store an empty string for the specific secret ID
	err := mockSecretMgr.StoreSecret(context.Background(), gatewayJWTSecretID, "")
	require.NoError(t, err)

	service := NewService(mockStore, mockSecretMgr, mockCfgMgr)
	require.NotNil(t, service)
	// Expect fallback key to be used
	assert.Equal(t, []byte("fallback-insecure-key-please-configure-secret"), service.jwtKey, "Service should use fallback key if secret is empty")
	// TODO: Add log capture to verify warning message
}

func TestNewService_JWTKeyLoad_ShortSecret(t *testing.T) {
	mockStore := NewMockStore()
	mockSecretMgr := NewMockSecretManager()
	mockCfgMgr := NewMockConfigManager(&config.RuntimeConfig{})

	shortKey := "short-key" // Less than 32 bytes
	err := mockSecretMgr.StoreSecret(context.Background(), gatewayJWTSecretID, shortKey)
	require.NoError(t, err)

	service := NewService(mockStore, mockSecretMgr, mockCfgMgr)
	require.NotNil(t, service)
	assert.Equal(t, []byte(shortKey), service.jwtKey, "Service should use the provided short key")
	// TODO: Add log capture to verify warning message about short key
}

func TestGetResolvedRolesForPrincipal(t *testing.T) {
	mockStore := NewMockStore()
	mockRuntimeCfg := &config.RuntimeConfig{
		IAMConfig: config.IAMConfig{
			Roles: []config.RoleConfig{ // Define some roles for completeness, though not directly used by getResolvedRolesForPrincipal
				{Name: "role_a", Permissions: []config.Permission{"perm_a"}},
				{Name: "role_b", Permissions: []config.Permission{"perm_b"}},
				{Name: "role_c", Permissions: []config.Permission{"perm_c"}},
				{Name: "group_role_x", Permissions: []config.Permission{"perm_x"}},
				{Name: "group_role_y", Permissions: []config.Permission{"perm_y"}},
			},
			RoleBindings: []config.RoleBindingConfig{}, // Will be populated per test case
		},
	}
	mockCfgManager := NewMockConfigManager(mockRuntimeCfg)
	// Secret manager is not directly used by getResolvedRolesForPrincipal, but NewService needs it.
	mockSecretMgr := NewMockSecretManager()
	_ = mockSecretMgr.StoreSecret(context.Background(), gatewayJWTSecretID, "test-jwt-signing-key-32-bytes-long")

	service := NewService(mockStore, mockSecretMgr, mockCfgManager)
	ctx := context.Background()

	// Helper to set user and group data
	setupUserAndGroups := func(userID string, email string, groupIDs []string, groupsData map[string]config.GroupConfig) {
		userCfg := config.UserConfig{ID: userID, Email: email, GroupIDs: groupIDs}
		userData, _ := json.Marshal(userCfg)
		_ = mockStore.Set(ctx, "iam/users/"+userID, userData)
		for groupID, groupCfg := range groupsData {
			groupData, _ := json.Marshal(groupCfg)
			_ = mockStore.Set(ctx, "iam/groups/"+groupID, groupData)
		}
	}

	t.Run("user with direct role bindings", func(t *testing.T) {
		userID := "user-direct-roles"
		setupUserAndGroups(userID, "direct@example.com", nil, nil)
		mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
			{PrincipalID: userID, PrincipalType: "user", RoleName: "role_a"},
			{PrincipalID: userID, PrincipalType: "user", RoleName: "role_b"},
		}
		roles, err := service.getResolvedRolesForPrincipal(ctx, userID, nil)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"role_a", "role_b"}, roles)
	})

	t.Run("user with group role bindings", func(t *testing.T) {
		userID := "user-group-roles"
		groupID1 := "group1-bound"
		groupID2 := "group2-bound"
		setupUserAndGroups(userID, "group@example.com", []string{groupID1, groupID2}, map[string]config.GroupConfig{
			groupID1: {ID: groupID1, Name: "Group 1 Bound"},
			groupID2: {ID: groupID2, Name: "Group 2 Bound"},
		})
		mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
			{PrincipalID: groupID1, PrincipalType: "group", RoleName: "group_role_x"},
			{PrincipalID: groupID2, PrincipalType: "group", RoleName: "group_role_y"},
			{PrincipalID: "other_group", PrincipalType: "group", RoleName: "role_c"}, // Should not be picked up
		}
		roles, err := service.getResolvedRolesForPrincipal(ctx, userID, []string{groupID1, groupID2})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"group_role_x", "group_role_y"}, roles)
	})

	t.Run("user with direct and group role bindings (deduplicated)", func(t *testing.T) {
		userID := "user-mixed-roles"
		groupID := "group-mixed"
		setupUserAndGroups(userID, "mixed@example.com", []string{groupID}, map[string]config.GroupConfig{
			groupID: {ID: groupID, Name: "Group Mixed"},
		})
		mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
			{PrincipalID: userID, PrincipalType: "user", RoleName: "role_a"},
			{PrincipalID: groupID, PrincipalType: "group", RoleName: "group_role_x"},
			{PrincipalID: groupID, PrincipalType: "group", RoleName: "role_a"}, // Duplicate via group
		}
		roles, err := service.getResolvedRolesForPrincipal(ctx, userID, []string{groupID})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"role_a", "group_role_x"}, roles)
	})

	t.Run("user with no bindings and no group bindings", func(t *testing.T) {
		userID := "user-no-roles-at-all"
		groupID := "group-unbound"
		setupUserAndGroups(userID, "noroles@example.com", []string{groupID}, map[string]config.GroupConfig{
			groupID: {ID: groupID, Name: "Group Unbound"},
		})
		mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
			{PrincipalID: "other_user", PrincipalType: "user", RoleName: "role_a"},
			{PrincipalID: "other_group", PrincipalType: "group", RoleName: "group_role_x"},
		}
		roles, err := service.getResolvedRolesForPrincipal(ctx, userID, []string{groupID})
		require.NoError(t, err)
		assert.Empty(t, roles)
	})

	t.Run("non-existent user", func(t *testing.T) {
		// User "user-non-existent" is not in mockStore
		mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
			{PrincipalID: "user-non-existent", PrincipalType: "user", RoleName: "role_a"},
		}
		// getResolvedRolesForPrincipal doesn't fetch user data itself, it relies on passed groupIDs.
		// If principalID is for a user, and it has direct bindings, those should be returned.
		// The check for user existence happens earlier or when groupIDs are needed.
		roles, err := service.getResolvedRolesForPrincipal(ctx, "user-non-existent", nil)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"role_a"}, roles, "Should still pick up direct bindings even if user not in store, as group IDs are nil")

		// If group IDs were expected but user not found to provide them, it might differ.
		// However, the current function signature takes groupIDs as an argument.
	})

	t.Run("user with groupID for non-existent group in store", func(t *testing.T) {
		userID := "user-bad-group"
		nonExistentGroupID := "group-does-not-exist"
		setupUserAndGroups(userID, "badgroup@example.com", []string{nonExistentGroupID}, nil) // Group not in store
		mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
			{PrincipalID: nonExistentGroupID, PrincipalType: "group", RoleName: "group_role_x"},
		}
		// The function iterates over provided groupIDs. It doesn't check if the group itself exists in the store.
		roles, err := service.getResolvedRolesForPrincipal(ctx, userID, []string{nonExistentGroupID})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"group_role_x"}, roles)
	})

	t.Run("role binding for a non-existent role name", func(t *testing.T) {
		userID := "user-unknown-role-binding"
		setupUserAndGroups(userID, "unknownrole@example.com", nil, nil)
		mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
			{PrincipalID: userID, PrincipalType: "user", RoleName: "role_that_is_not_defined_in_roles_list"},
		}
		roles, err := service.getResolvedRolesForPrincipal(ctx, userID, nil)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"role_that_is_not_defined_in_roles_list"}, roles)
	})

	t.Run("service account principal type", func(t *testing.T) {
		saID := "sa-test-account"
		// Service accounts might not have UserConfig or GroupIDs in the same way.
		// getResolvedRolesForPrincipal primarily uses principalID for direct user/SA bindings,
		// and userGroupIDs for group bindings. For SA, userGroupIDs would be nil.
		mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{
			{PrincipalID: saID, PrincipalType: "serviceaccount", RoleName: "role_c"},
		}
		roles, err := service.getResolvedRolesForPrincipal(ctx, saID, nil) // No group IDs for SA
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"role_c"}, roles)
	})

	// Clear bindings for subsequent tests if TestCheckPermission runs after this in the same package.
	mockRuntimeCfg.IAMConfig.RoleBindings = []config.RoleBindingConfig{}
}
