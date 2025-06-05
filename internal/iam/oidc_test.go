package iam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/secrets" // Import for SecretManagementService
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockOIDCProvider represents a mock OIDC provider.
type mockOIDCProvider struct {
	server           *httptest.Server
	issuer           string
	authEndpoint     string
	tokenEndpoint    string
	userinfoEndpoint string
	jwksEndpoint     string
	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	keyID            string

	// Control fields for testing
	returnErrorOnTokenEndpoint    bool
	returnErrorOnUserinfoEndpoint bool
	customTokenResponse           func() map[string]interface{} // Made it a func to allow dynamic values like nonce
	customUserinfoResponse        map[string]interface{}
}

// newMockOIDCProvider creates and starts a new mock OIDC provider.
func newMockOIDCProvider(t *testing.T) *mockOIDCProvider {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mock := &mockOIDCProvider{
		privateKey: privKey,
		publicKey:  &privKey.PublicKey,
		keyID:      "mock-key-id",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", mock.handleDiscovery)
	mux.HandleFunc("/jwks", mock.handleJWKS)
	mux.HandleFunc("/authorize", mock.handleAuthorize)
	mux.HandleFunc("/token", mock.handleToken)
	mux.HandleFunc("/userinfo", mock.handleUserinfo)

	mock.server = httptest.NewServer(mux)
	mock.issuer = mock.server.URL
	mock.authEndpoint = mock.server.URL + "/authorize"
	mock.tokenEndpoint = mock.server.URL + "/token"
	mock.userinfoEndpoint = mock.server.URL + "/userinfo"
	mock.jwksEndpoint = mock.server.URL + "/jwks"

	t.Logf("Mock OIDC provider started at: %s", mock.server.URL)
	return mock
}

func (m *mockOIDCProvider) Close() {
	m.server.Close()
}

func (m *mockOIDCProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"issuer":                                m.issuer,
		"authorization_endpoint":                m.authEndpoint,
		"token_endpoint":                        m.tokenEndpoint,
		"userinfo_endpoint":                     m.userinfoEndpoint,
		"jwks_uri":                              m.jwksEndpoint,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile", "groups"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                      []string{"aud", "email", "email_verified", "exp", "iat", "iss", "name", "sub", "groups"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockOIDCProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	exponentBytes := []byte{1, 0, 1}

	jwk := map[string]string{
		"kty": "RSA",
		"kid": m.keyID,
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(m.publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponentBytes),
	}
	bigE := big.NewInt(int64(m.publicKey.E))
	jwk["e"] = base64.RawURLEncoding.EncodeToString(bigE.Bytes())

	resp := map[string]interface{}{"keys": []interface{}{jwk}}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockOIDCProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	code := "mock-auth-code-for-" + state

	parsedRedirectURI, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	query := parsedRedirectURI.Query()
	query.Set("code", code)
	query.Set("state", state)
	parsedRedirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, parsedRedirectURI.String(), http.StatusFound)
}

func (m *mockOIDCProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if m.returnErrorOnTokenEndpoint {
		http.Error(w, "mock token endpoint error", http.StatusInternalServerError)
		return
	}
	if m.customTokenResponse != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.customTokenResponse())
		return
	}

	r.ParseForm()
	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, `{"error":"invalid_request", "error_description":"code is missing"}`, http.StatusBadRequest)
		return
	}

	idTokenClaims := jwt.MapClaims{
		"iss":    m.issuer,
		"sub":    "mock-user-sub-from-" + code,
		"aud":    "mock-client-id",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"email":  "mockuser@example.com",
		"name":   "Mock User",
		"groups": []string{"group1", "group2"},
	}
	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
	idToken.Header["kid"] = m.keyID
	idTokenString, err := idToken.SignedString(m.privateKey)
	if err != nil {
		http.Error(w, "Failed to sign ID token", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"access_token": "mock-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idTokenString,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockOIDCProvider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	if m.returnErrorOnUserinfoEndpoint {
		http.Error(w, "mock userinfo endpoint error", http.StatusInternalServerError)
		return
	}
	if m.customUserinfoResponse != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.customUserinfoResponse)
		return
	}
	resp := map[string]interface{}{
		"sub":    "mock-user-sub-from-userinfo",
		"email":  "userinfo@example.com",
		"name":   "User From Userinfo",
		"groups": []string{"group_info_A", "group_info_B"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// newTestSecretManager creates a real secrets.SecretManagementService with a mock store for testing.
func newTestSecretManager(t *testing.T) secrets.SecretManagementService {
	mockStore := NewMockStore()                                                            // from iam_test.go
	encryptionKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex chars
	sm, err := secrets.NewSecretManager(mockStore, encryptionKeyHex, "local", nil)         // NewSecretManager now returns (SecretManagementService, error)
	require.NoError(t, err)
	return sm
}

func TestNewOIDCAuthenticator_Success(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "oidc-client-secret-id", "mock-client-secret-value")
	require.NoError(t, err)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "test-oidc-provider",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "oidc-client-secret-id",
		RedirectURL:          "http://localhost/callback",
	}
	iamService := newTestIAMServiceForOIDC(t, nil)

	client, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Equal(t, oidcProviderCfg.ClientID, client.clientID)
	assert.NotNil(t, client.provider)
}

func TestNewOIDCAuthenticator_DiscoveryFailure(t *testing.T) {
	secretMgr := newTestSecretManager(t)
	_ = secretMgr.StoreSecret(context.Background(), "oidc-client-secret-id", "mock-client-secret-value")
	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "test-oidc-provider-fail",
		IssuerURL:            "http://localhost:12345/nonexistent-issuer",
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "oidc-client-secret-id",
		RedirectURL:          "http://localhost/callback",
	}

	_, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create OIDC provider")
}

func TestHandleOIDCLogin(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "login-secret-id", "login-secret-value")
	require.NoError(t, err)
	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "login-provider",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "login-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
		Scopes:               []string{"openid", "email", "profile"},
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/login/oidc", nil)
	rr := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	require.NotEmpty(t, location)

	parsedURL, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, mockProvider.authEndpoint, strings.Split(parsedURL.String(), "?")[0])
	assert.Equal(t, oidcProviderCfg.ClientID, parsedURL.Query().Get("client_id"))
	assert.Equal(t, oidcProviderCfg.RedirectURL, parsedURL.Query().Get("redirect_uri"))
	assert.Equal(t, "code", parsedURL.Query().Get("response_type"))
	assert.Contains(t, parsedURL.Query().Get("scope"), "openid")
	assert.Contains(t, parsedURL.Query().Get("scope"), "email")
	assert.Contains(t, parsedURL.Query().Get("scope"), "profile")
	assert.NotEmpty(t, parsedURL.Query().Get("state"))

	cookies := rr.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "State cookie should be set")
	assert.NotEmpty(t, stateCookie.Value)
	assert.Equal(t, "/", stateCookie.Path)
	assert.True(t, stateCookie.HttpOnly)
}

func newTestIAMServiceForOIDC(t *testing.T, cfgManager ConfigManagerInterface) *Service {
	mockStore := NewMockStore()
	iamMockSecretMgr := NewMockSecretManager() // This is the mock from iam_test.go, not secrets.SecretManagementService
	err := iamMockSecretMgr.StoreSecret(context.Background(), gatewayJWTSecretID, "test-jwt-signing-key-32-bytes-long-for-oidc")
	require.NoError(t, err)

	if cfgManager == nil {
		defaultRuntimeCfg := &config.RuntimeConfig{
			IAMConfig: config.IAMConfig{
				Roles: []config.RoleConfig{
					{Name: "admin", Permissions: []config.Permission{"*:*"}},
					{Name: "viewer", Permissions: []config.Permission{"*:read"}},
					{Name: "default_user_role", Permissions: []config.Permission{"profile:read"}},
				},
				OIDCProviders: []config.OIDCProviderConfig{},
			},
		}
		cfgManager = NewMockConfigManager(defaultRuntimeCfg)
	}
	iamSvc := NewService(mockStore, iamMockSecretMgr, cfgManager) // NewService expects iam.SecretManagerInterface
	require.NotNil(t, iamSvc)
	return iamSvc
}

func TestHandleOIDCCallback_Success(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)

	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
		Scopes:               []string{"openid", "email", "profile", "groups"},
		GroupMappings:        map[string]string{"group1": "internal_group_one"},
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)

	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=mock-auth-code-for-%s&state=%s", stateCookie.Value, stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)

	callbackRR := httptest.NewRecorder()

	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss":    mockProvider.issuer,
			"sub":    "mock-user-sub-from-code",
			"aud":    oidcProviderCfg.ClientID,
			"exp":    time.Now().Add(time.Hour).Unix(),
			"iat":    time.Now().Unix(),
			"email":  "callbackuser@example.com",
			"name":   "Callback User From Token",
			"groups": []string{"group1", "group_unmapped"},
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(mockProvider.privateKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token-callback",
			"token_type":   "Bearer",
			"id_token":     idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusOK, callbackRR.Code, "Callback should return 200 OK with JSON")

	var respBody map[string]interface{}
	err = json.Unmarshal(callbackRR.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, "OIDC authentication successful", respBody["message"])
	assert.NotEmpty(t, respBody["gateway_token"])
	assert.Equal(t, "callbackuser@example.com", respBody["email"])

	mockStore := iamService.store.(*MockStore)
	userIDBytes, err := mockStore.Get(context.Background(), "iam/users_by_email/callbackuser@example.com")
	require.NoError(t, err, "User email index should exist")
	userID := string(userIDBytes)

	userDataBytes, err := mockStore.Get(context.Background(), "iam/users/"+userID)
	require.NoError(t, err, "User data should exist")
	var provisionedUser config.UserConfig
	err = json.Unmarshal(userDataBytes, &provisionedUser)
	require.NoError(t, err)
	assert.Equal(t, "callbackuser@example.com", provisionedUser.Email)
	assert.Contains(t, provisionedUser.GroupIDs, "internal_group_one")
}

func TestHandleOIDCCallback_StateMismatch(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)
	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider-state-mismatch",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)

	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "State cookie should be set from login")

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=somecode&state=tampered-state-value")
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)

	callbackRR := httptest.NewRecorder()
	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusBadRequest, callbackRR.Code, "Callback should return 400 Bad Request on state mismatch")
	assert.Contains(t, callbackRR.Body.String(), "state mismatch")
}

func TestHandleOIDCCallback_CodeExchangeError(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)
	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider-code-error",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)

	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "State cookie should be set from login")

	mockProvider.returnErrorOnTokenEndpoint = true
	defer func() { mockProvider.returnErrorOnTokenEndpoint = false }()

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=valid-looking-code&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)

	callbackRR := httptest.NewRecorder()
	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusInternalServerError, callbackRR.Code, "Callback should return 500 on code exchange failure")
	assert.Contains(t, callbackRR.Body.String(), "Failed to exchange OIDC token")
}

func TestHandleOIDCCallback_IDTokenBadSignature(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	badSigningKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	secretMgr := newTestSecretManager(t)
	err = secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)
	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider-bad-sig",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)
	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss": mockProvider.issuer, "sub": "user-bad-sig", "aud": oidcProviderCfg.ClientID,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "email": "badsig@example.com",
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(badSigningKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token-bad-sig", "token_type": "Bearer", "id_token": idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=code-for-bad-sig&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()
	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusInternalServerError, callbackRR.Code)
	assert.Contains(t, callbackRR.Body.String(), "Failed to verify OIDC ID Token")
	assert.Contains(t, callbackRR.Body.String(), "failed to verify signature")
}

func TestHandleOIDCCallback_IDTokenExpired(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)
	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider-expired-token",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)
	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss": mockProvider.issuer, "sub": "user-expired-token", "aud": oidcProviderCfg.ClientID,
			"exp": time.Now().Add(-time.Hour).Unix(),
			"iat": time.Now().Add(-2 * time.Hour).Unix(), "email": "expired@example.com",
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(mockProvider.privateKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token-expired", "token_type": "Bearer", "id_token": idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=code-for-expired-token&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()
	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusInternalServerError, callbackRR.Code)
	assert.Contains(t, callbackRR.Body.String(), "Failed to verify OIDC ID Token")
	assert.Contains(t, callbackRR.Body.String(), "token is expired")
}

func TestHandleOIDCCallback_IDTokenIssuerMismatch(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)
	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider-issuer-mismatch",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)
	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss": "https://another-issuer.com",
			"sub": "user-issuer-mismatch", "aud": oidcProviderCfg.ClientID,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "email": "issuer@example.com",
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(mockProvider.privateKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token-issuer-mismatch", "token_type": "Bearer", "id_token": idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=code-for-issuer-mismatch&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()
	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusInternalServerError, callbackRR.Code)
	assert.Contains(t, callbackRR.Body.String(), "Failed to verify OIDC ID Token")
	assert.Contains(t, callbackRR.Body.String(), "id token issued by a different provider")
}

func TestHandleOIDCCallback_IDTokenAudienceMismatch(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)
	iamService := newTestIAMServiceForOIDC(t, nil)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider-aud-mismatch",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)
	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss": mockProvider.issuer, "sub": "user-aud-mismatch",
			"aud": "another-client-id",
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "email": "aud@example.com",
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(mockProvider.privateKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token-aud-mismatch", "token_type": "Bearer", "id_token": idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=code-for-aud-mismatch&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()
	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusInternalServerError, callbackRR.Code)
	assert.Contains(t, callbackRR.Body.String(), "Failed to verify OIDC ID Token")
	assert.Contains(t, callbackRR.Body.String(), "expected audience")
}

func TestHandleOIDCCallback_UserProvisioningError(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)

	iamService := newTestIAMServiceForOIDC(t, nil)
	mockStore := iamService.store.(*MockStore)

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider-prov-error",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)
	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss": mockProvider.issuer, "sub": "user-prov-error", "aud": oidcProviderCfg.ClientID,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "email": "proverror@example.com",
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(mockProvider.privateKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token-prov-error", "token_type": "Bearer", "id_token": idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	mockStore.err = fmt.Errorf("database unavailable")
	defer func() { mockStore.err = nil }()

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=code-for-prov-error&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()
	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusInternalServerError, callbackRR.Code)
	assert.Contains(t, callbackRR.Body.String(), "Failed to provision user")
	assert.Contains(t, callbackRR.Body.String(), "database unavailable")
}

func TestHandleOIDCCallback_GatewayJWTIssuanceError(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "callback-secret-id", "callback-secret-value")
	require.NoError(t, err)

	iamService := newTestIAMServiceForOIDC(t, nil)
	iamService.jwtKey = []byte{}

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "callback-provider-jwt-issue-error",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "callback-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)
	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)

	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss": mockProvider.issuer, "sub": "user-jwt-issue-error", "aud": oidcProviderCfg.ClientID,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "email": "jwtissue@example.com",
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(mockProvider.privateKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token-jwt-issue-error", "token_type": "Bearer", "id_token": idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=code-for-jwt-issue-error&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()
	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusInternalServerError, callbackRR.Code)
	assert.Contains(t, callbackRR.Body.String(), "Failed to issue gateway token")
}

// TODO: Add more tests for HandleOIDCCallback:
// - Userinfo fetch error (if GetClaimsFromUserInfo is true and mockProvider.returnErrorOnUserinfoEndpoint = true)
// - JWT issuance error (e.g., iamService.IssueGatewayJWT returns error)

func TestHandleOIDCCallback_NonceNotFound(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "nonce-test-secret-id", "nonce-test-secret-value")
	require.NoError(t, err)

	iamService := newTestIAMServiceForOIDC(t, nil)
	// Do NOT store the nonce in the mock store for this test case.
	// The oidcStateStore is iamService.store, which is a MockStore.
	// By default, MockStore.Get will return store.ErrNotFound if key is not in its map.

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "nonce-not-found-provider",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "nonce-test-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	// Simulate login to get a state cookie
	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq)
	require.Equal(t, http.StatusFound, loginRR.Code)
	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "State cookie should be set")

	// Prepare callback request
	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=some-code&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()

	// Mock token response (nonce in token won't matter as store lookup fails first)
	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss":   mockProvider.issuer,
			"sub":   "user-nonce-test",
			"aud":   oidcProviderCfg.ClientID,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"nonce": "some-nonce-value", // This nonce won't be found in store
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(mockProvider.privateKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token",
			"id_token":     idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusBadRequest, callbackRR.Code)
	assert.Contains(t, callbackRR.Body.String(), "Invalid or expired state (nonce missing)")
}

func TestHandleOIDCCallback_NonceMismatch(t *testing.T) {
	mockProvider := newMockOIDCProvider(t)
	defer mockProvider.Close()

	secretMgr := newTestSecretManager(t)
	err := secretMgr.StoreSecret(context.Background(), "nonce-mismatch-secret-id", "nonce-mismatch-secret-value")
	require.NoError(t, err)

	iamService := newTestIAMServiceForOIDC(t, nil)
	// mockStore := iamService.store.(*MockStore) // Get the underlying MockStore - not explicitly used in this test path

	oidcProviderCfg := config.OIDCProviderConfig{
		ID:                   "nonce-mismatch-provider",
		IssuerURL:            mockProvider.issuer,
		ClientID:             "mock-client-id",
		ClientSecretSecretID: "nonce-mismatch-secret-id",
		RedirectURL:          "http://localhost:8080/auth/oidc/callback",
	}
	oidcAuthenticator, err := NewOIDCAuthenticator(context.Background(), oidcProviderCfg, iamService, secretMgr)
	require.NoError(t, err)

	// Simulate login to get a state cookie and store the "expected" nonce
	loginReq := httptest.NewRequest("GET", "/login/oidc", nil)
	loginRR := httptest.NewRecorder()
	oidcAuthenticator.HandleLogin(loginRR, loginReq) // This will store a nonce like "nonce:stateValue"
	require.Equal(t, http.StatusFound, loginRR.Code)

	var stateCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "State cookie should be set")

	// Ensure the "expected" nonce is in the store (HandleLogin should do this)
	// We can retrieve it to confirm, or just trust HandleLogin's side effect for this test.
	// For this test, we'll rely on HandleLogin having stored it.

	// Prepare callback request
	callbackURL := fmt.Sprintf("/auth/oidc/callback?code=some-code&state=%s", stateCookie.Value)
	callbackReq := httptest.NewRequest("GET", callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()

	// Mock token response with a *different* nonce
	mockProvider.customTokenResponse = func() map[string]interface{} {
		idTokenClaims := jwt.MapClaims{
			"iss":   mockProvider.issuer,
			"sub":   "user-nonce-mismatch",
			"aud":   oidcProviderCfg.ClientID,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"nonce": "different-nonce-than-stored", // This nonce will not match the one stored by HandleLogin
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		idToken.Header["kid"] = mockProvider.keyID
		idTokenString, signErr := idToken.SignedString(mockProvider.privateKey)
		require.NoError(t, signErr)
		return map[string]interface{}{
			"access_token": "mock-access-token",
			"id_token":     idTokenString,
		}
	}
	defer func() { mockProvider.customTokenResponse = nil }()

	oidcAuthenticator.HandleCallback(callbackRR, callbackReq)

	assert.Equal(t, http.StatusBadRequest, callbackRR.Code)
	assert.Contains(t, callbackRR.Body.String(), "Nonce mismatch")
}
