package iam

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/secrets" // Added for SecretManager
	// "github.com/openpons/gateway/internal/store" // For user provisioning
)

// OIDCAuthenticator handles OIDC authentication flows.
type OIDCAuthenticator struct {
	provider       *oidc.Provider
	providerConfig config.OIDCProviderConfig // Store the original config for access to GroupMappings etc.
	oauth2Config   oauth2.Config             // This will hold the clientSecret internally after fetching
	clientID       string
	redirectURL    string
	iamService     *Service // To provision users, issue gateway JWTs
	secretManager  secrets.SecretManagementService
	// store         store.Store // For session state or user storage
}

// NewOIDCAuthenticator creates a new OIDC authenticator for a given provider config.
func NewOIDCAuthenticator(ctx context.Context, cfg config.OIDCProviderConfig, iamSvc *Service, sm secrets.SecretManagementService /*, s store.Store*/) (*OIDCAuthenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for issuer %s: %w", cfg.IssuerURL, err)
	}

	clientSecret, err := sm.GetSecret(ctx, cfg.ClientSecretSecretID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve OIDC client secret for ID %s: %w", cfg.ClientSecretSecretID, err)
	}
	if clientSecret == "" { // Should be caught by GetSecret error, but defensive
		return nil, fmt.Errorf("retrieved OIDC client secret for ID %s is empty", cfg.ClientSecretSecretID)
	}

	return &OIDCAuthenticator{
		providerConfig: cfg, // Store the original provider config
		provider:       provider,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: clientSecret,
			RedirectURL:  cfg.RedirectURL, // This must be registered with the OIDC provider
			Endpoint:     provider.Endpoint(),
			Scopes:       append([]string{oidc.ScopeOpenID, "profile", "email"}, cfg.Scopes...), // Ensure standard scopes + configured ones
		},
		clientID:      cfg.ClientID,
		redirectURL:   cfg.RedirectURL,
		iamService:    iamSvc,
		secretManager: sm,
		// store: s,
	}, nil
}

// HandleLogin redirects the user to the OIDC provider's authorization endpoint.
func (a *OIDCAuthenticator) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state and nonce, store them in a short-lived cookie or server-side session.
	state, err := generateRandomString(32)
	if err != nil {
		http.Error(w, "Failed to generate state for OIDC login", http.StatusInternalServerError)
		return
	}
	// State is stored in a secure cookie.
	// Nonce is optional if PKCE is used or not strictly required by the provider.

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   r.TLS != nil, // Set Secure flag if served over HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// Optional: PKCE for more secure auth code flow
	// codeVerifier := oauth2.GenerateVerifier()
	// store codeVerifier in cookie
	// codeChallenge := oauth2.S256ChallengeOption(codeVerifier)
	// authURL :=รัฐ.oauth2Config.AuthCodeURL(state, codeChallenge)

	authURL := a.oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback processes the OIDC provider's response after user authentication.
func (a *OIDCAuthenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check state cookie
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil {
		http.Error(w, "OIDC callback error: missing state cookie", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "OIDC callback error: state mismatch", http.StatusBadRequest)
		return
	}
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{Name: "oidc_state", Value: "", Path: "/", MaxAge: -1})

	oauth2Token, err := a.oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange OIDC token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in OIDC token response", http.StatusInternalServerError)
		return
	}

	oidcConfig := &oidc.Config{ClientID: a.clientID}
	idToken, err := a.provider.Verifier(oidcConfig).Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify OIDC ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract claims
	var claims struct {
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Name          string   `json:"name,omitempty"`
		Groups        []string `json:"groups,omitempty"` // Or provider-specific group claim
		// Add other claims as needed
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse OIDC claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// User Provisioning based on claims (email as primary identifier)
	user, err := a.iamService.ProvisionUserFromOIDC(ctx, claims.Email, claims.Name, claims.Groups, a.providerConfig.GroupMappings)
	if err != nil {
		http.Error(w, "Failed to provision user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("OIDC User Authenticated and provisioned: Email=%s, Name=%s, ID=%s", user.Email, claims.Name, user.ID)
	userID := user.ID // Use actual user ID from provisioning for JWT

	// Issue Gateway JWT
	gatewayToken, err := a.iamService.IssueGatewayJWT(userID, claims.Email, claims.Groups)
	if err != nil {
		http.Error(w, "Failed to issue gateway token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// For MVP, just return a success message or redirect to a frontend app with token

	// Example: Set a session cookie with the gateway token or redirect with token
	// http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: gatewayToken, Path: "/", HttpOnly: true, Secure: r.TLS!=nil})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":             "OIDC authentication successful",
		"email":               claims.Email,
		"name":                claims.Name,
		"id_token_expiry":     idToken.Expiry,
		"access_token_expiry": oauth2Token.Expiry,
		"gateway_token":       gatewayToken, // Send this in a secure way (e.g. not in body for prod)
	})
}

// generateRandomString creates a securely random, URL-safe string.
func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Note: JWT handling (IssueGatewayJWT and ValidateGatewayJWT) is implemented
// in the IAM service (internal/iam/iam.go) and used by this OIDC authenticator.
// The GatewayJWTClaims struct is also defined in the IAM package.
