// Package iam handles Identity and Access Management for the OpenPons Gateway.
package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors" // Ensured
	"fmt"
	"log"
	"net/http"
	"net/mail" // Added for email validation
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/openpons/gateway/internal/config" // Will be used by ConfigManagerInterface
	"github.com/openpons/gateway/internal/store"
)

// Predefined errors
var (
	ErrRoleAlreadyExists           = errors.New("role already exists")
	ErrRoleNotFound                = errors.New("role not found")
	ErrGroupAlreadyExists          = errors.New("group already exists")
	ErrGroupNotFound               = errors.New("group not found")
	ErrUserNotFound                = errors.New("user not found")
	ErrRoleBindingAlreadyExists    = errors.New("role binding already exists")
	ErrRoleBindingNotFound         = errors.New("role binding not found")
	ErrInvalidPrincipalType        = errors.New("invalid principal type")
	ErrServiceAccountAlreadyExists = errors.New("service account with this name already exists")
	ErrServiceAccountNotFound      = errors.New("service account not found")
	ErrUserAlreadyExists           = errors.New("user with this email already exists") // New error for user creation
	ErrAPIKeyNotFound              = errors.New("api key not found")                   // New error for API Key operations
	// Add other IAM specific errors here
)

// GatewayJWTClaims defines the structure for JWT claims used by the OpenPons Gateway.
type GatewayJWTClaims struct {
	UserID string   `json:"uid"`
	Email  string   `json:"email"`
	Groups []string `json:"groups,omitempty"`
	Roles  []string `json:"roles,omitempty"` // Roles resolved by OpenPons IAM
	jwt.RegisteredClaims
}

// SecretManagerInterface defines the methods iam.Service needs from a secrets manager.
type SecretManagerInterface interface {
	GetSecret(ctx context.Context, id string) (string, error)
	StoreSecret(ctx context.Context, id string, value string) error
}

// ConfigManagerInterface defines the methods iam.Service needs from a config manager.
type ConfigManagerInterface interface {
	GetCurrentConfig() *config.RuntimeConfig
	Subscribe() <-chan *config.RuntimeConfig
	ReloadConfig(ctx context.Context) error // Added to allow IAM service to trigger a config reload
}

type ContextKey string

const (
	apiKeyPrefix                     = "opk_"
	apiKeyByteLength                 = 32
	ContextKeyPrincipalID ContextKey = "principalID"
	ContextKeyAuthMethod  ContextKey = "authMethod"
	ContextKeyAuthInfo    ContextKey = "authInfo"
	AuthMethodAPIKey                 = "apikey"
	AuthMethodJWT                    = "jwt"
	gatewayJWTSecretID               = "openpons_gateway_jwt_signing_key"
)

type Service struct {
	store               store.Store
	secretManager       SecretManagerInterface
	rolesLock           sync.RWMutex
	roles               map[string]*Role
	groupsLock          sync.RWMutex
	groups              map[string]*Group
	usersLock           sync.RWMutex
	users               map[string]*User
	roleBindingsLock    sync.RWMutex
	roleBindings        map[string]*RoleBinding
	serviceAccountsLock sync.RWMutex               // New lock for service accounts
	serviceAccounts     map[string]*ServiceAccount // New cache for service accounts (keyed by ID)
	jwtKey              []byte
	configManager       ConfigManagerInterface
}

type ServiceInterface interface {
	CheckPermission(ctx context.Context, principalID string, authInfo interface{}, requiredPerm config.Permission) bool
	AuthMiddleware(next http.Handler) http.Handler                                        // Added AuthMiddleware
	AuthzMiddleware(requiredPermission config.Permission) func(http.Handler) http.Handler // Added AuthzMiddleware
}

func NewService(s store.Store, sm SecretManagerInterface, cm ConfigManagerInterface) *Service {
	iamSvc := &Service{
		store:           s,
		secretManager:   sm,
		configManager:   cm,
		roles:           make(map[string]*Role),
		groups:          make(map[string]*Group),
		users:           make(map[string]*User),
		roleBindings:    make(map[string]*RoleBinding),
		serviceAccounts: make(map[string]*ServiceAccount), // Initialize service accounts cache
	}
	iamSvc.loadDefaultRolesAndPermissions() // Loads default roles into cache

	// Load entities from store
	startupCtx := context.Background()
	iamSvc.loadRolesFromStore(startupCtx) // Load stored roles, potentially overwriting defaults
	iamSvc.loadUsersFromStore(startupCtx)
	iamSvc.loadGroupsFromStore(startupCtx)
	iamSvc.loadRoleBindingsFromStore(startupCtx)
	iamSvc.loadServiceAccountsFromStore(startupCtx)
	// TODO for loadUsersFromStore: also rebuild email->userID index if not persisted or to verify consistency.

	keyStr, err := sm.GetSecret(startupCtx, gatewayJWTSecretID)
	if err != nil {
		log.Printf("IAM: WARNING - Failed to load JWT signing key (ID: %s): %v. JWTs cannot be issued/validated reliably.", gatewayJWTSecretID, err)
		iamSvc.jwtKey = []byte("fallback-insecure-key-please-configure-secret")
	} else if keyStr == "" {
		log.Printf("IAM: WARNING - JWT signing key (ID: %s) is empty. JWTs cannot be issued/validated reliably.", gatewayJWTSecretID)
		iamSvc.jwtKey = []byte("fallback-insecure-key-please-configure-secret")
	} else {
		iamSvc.jwtKey = []byte(keyStr)
		log.Printf("IAM: JWT signing key (ID: %s) loaded successfully.", gatewayJWTSecretID)
	}
	if len(iamSvc.jwtKey) < 32 && string(iamSvc.jwtKey) == "fallback-insecure-key-please-configure-secret" {
		log.Println("IAM: WARNING - Using fallback insecure JWT signing key. Configure a strong key in secrets manager.")
	} else if len(iamSvc.jwtKey) < 32 {
		log.Printf("IAM: WARNING - Loaded JWT signing key (ID: %s) is too short (%d bytes). Recommend at least 32 bytes.", gatewayJWTSecretID, len(iamSvc.jwtKey))
	}

	return iamSvc
}

func (s *Service) loadDefaultRolesAndPermissions() {
	s.rolesLock.Lock()
	defer s.rolesLock.Unlock()
	s.roles["admin"] = &Role{Name: "admin", Permissions: []Permission{"*:*"}, Description: "Admin role"}
	s.roles["viewer"] = &Role{Name: "viewer", Permissions: []Permission{"*:read"}, Description: "Viewer role"}
	s.roles["model_operator"] = &Role{
		Name:        "model_operator",
		Permissions: []Permission{"proxy:invoke:*", "models:read", "providers:read", "routes:read"},
		Description: "Operator role for models",
	}
	log.Println("IAM: Loaded default roles into memory.")
}

// loadUsersFromStore loads users from the persistent store into the in-memory cache.
func (s *Service) loadUsersFromStore(ctx context.Context) {
	s.usersLock.Lock()
	defer s.usersLock.Unlock()

	userEntries, err := s.store.List(ctx, "iam/users/")
	if err != nil {
		log.Printf("IAM: Error listing users from store: %v", err)
		return
	}
	count := 0
	for key, data := range userEntries {
		var user User
		if errUnmarshal := json.Unmarshal(data, &user); errUnmarshal != nil {
			log.Printf("IAM: Error unmarshalling user data from key %s: %v", key, errUnmarshal)
			continue
		}
		s.users[user.ID] = &user
		count++
	}
	if count > 0 {
		log.Printf("IAM: Loaded %d users from store.", count)
	}
}

// loadGroupsFromStore loads groups from the persistent store into the in-memory cache.
func (s *Service) loadGroupsFromStore(ctx context.Context) {
	s.groupsLock.Lock()
	defer s.groupsLock.Unlock()

	groupEntries, err := s.store.List(ctx, "iam/groups/")
	if err != nil {
		log.Printf("IAM: Error listing groups from store: %v", err)
		return
	}
	count := 0
	for key, data := range groupEntries {
		var group Group
		if errUnmarshal := json.Unmarshal(data, &group); errUnmarshal != nil {
			log.Printf("IAM: Error unmarshalling group data from key %s: %v", key, errUnmarshal)
			continue
		}
		s.groups[group.ID] = &group
		count++
	}
	if count > 0 {
		log.Printf("IAM: Loaded %d groups from store.", count)
	}
}

// loadRolesFromStore loads roles from the persistent store into the in-memory cache.
// This may overwrite default roles if names conflict, assuming store is source of truth for customizations.
func (s *Service) loadRolesFromStore(ctx context.Context) {
	s.rolesLock.Lock()
	defer s.rolesLock.Unlock()

	roleEntries, err := s.store.List(ctx, "iam/roles/")
	if err != nil {
		log.Printf("IAM: Error listing roles from store: %v", err)
		return
	}
	count := 0
	for key, data := range roleEntries {
		var role Role
		if errUnmarshal := json.Unmarshal(data, &role); errUnmarshal != nil {
			log.Printf("IAM: Error unmarshalling role data from key %s: %v", key, errUnmarshal)
			continue
		}
		s.roles[role.Name] = &role // Keyed by name
		count++
	}
	if count > 0 {
		log.Printf("IAM: Loaded %d roles from store (may overwrite defaults).", count)
	}
}

// loadRoleBindingsFromStore loads role bindings from the persistent store into the in-memory cache.
func (s *Service) loadRoleBindingsFromStore(ctx context.Context) {
	s.roleBindingsLock.Lock()
	defer s.roleBindingsLock.Unlock()

	bindingEntries, err := s.store.List(ctx, "iam/rolebindings/")
	if err != nil {
		log.Printf("IAM: Error listing role bindings from store: %v", err)
		return
	}
	count := 0
	for key, data := range bindingEntries {
		var binding RoleBinding
		if errUnmarshal := json.Unmarshal(data, &binding); errUnmarshal != nil {
			log.Printf("IAM: Error unmarshalling role binding data from key %s: %v", key, errUnmarshal)
			continue
		}
		s.roleBindings[binding.ID] = &binding
		count++
	}
	if count > 0 {
		log.Printf("IAM: Loaded %d role bindings from store.", count)
	}
}

// loadServiceAccountsFromStore loads service accounts from the persistent store into the in-memory cache.
func (s *Service) loadServiceAccountsFromStore(ctx context.Context) {
	s.serviceAccountsLock.Lock()
	defer s.serviceAccountsLock.Unlock()

	saEntries, err := s.store.List(ctx, "iam/serviceaccounts/")
	if err != nil {
		log.Printf("IAM: Error listing service accounts from store: %v", err)
		return
	}
	count := 0
	for key, data := range saEntries {
		var sa ServiceAccount
		if errUnmarshal := json.Unmarshal(data, &sa); errUnmarshal != nil {
			log.Printf("IAM: Error unmarshalling service account data from key %s: %v", key, errUnmarshal)
			continue
		}
		s.serviceAccounts[sa.ID] = &sa
		count++
	}
	if count > 0 {
		log.Printf("IAM: Loaded %d service accounts from store.", count)
	}
}

func (s *Service) ProvisionUserFromOIDC(ctx context.Context, email, name string, oidcGroups []string, groupMappings map[string]string) (*config.UserConfig, error) {
	userKey := "iam/users_by_email/" + email
	userIDBytes, err := s.store.Get(ctx, userKey)
	var user *config.UserConfig
	var userID string

	if err == nil && len(userIDBytes) > 0 {
		userID = string(userIDBytes)
		userDataKey := "iam/users/" + userID
		userData, errGet := s.store.Get(ctx, userDataKey)
		if errGet == nil {
			if json.Unmarshal(userData, &user) != nil {
				user = nil
			}
		} else {
			user = nil
		}
	}

	if user == nil {
		userID = "user-" + uuid.New().String()
		user = &config.UserConfig{ID: userID, Email: email, Status: "active", CreatedAt: time.Now().UTC()}
		if errIdx := s.store.Set(ctx, userKey, []byte(userID)); errIdx != nil {
			log.Printf("IAM: Failed to store email index for new user %s: %v", email, errIdx)
		}
	}

	newGroupIDs := make(map[string]bool)
	if len(oidcGroups) > 0 && len(groupMappings) > 0 {
		for _, oidcGroup := range oidcGroups {
			if internalGroupID, ok := groupMappings[oidcGroup]; ok {
				newGroupIDs[internalGroupID] = true
			}
		}
	}
	user.GroupIDs = []string{}
	for id := range newGroupIDs {
		user.GroupIDs = append(user.GroupIDs, id)
	}

	user.UpdatedAt = time.Now().UTC()
	userData, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("marshal user %s: %w", email, err)
	}
	if err := s.store.Set(ctx, "iam/users/"+userID, userData); err != nil {
		return nil, fmt.Errorf("store user %s: %w", email, err)
	}
	return user, nil
}

func (s *Service) getResolvedRolesForPrincipal(ctx context.Context, principalID string, userGroupIDs []string) ([]string, error) {
	if s.configManager == nil {
		log.Println("IAM: ConfigManager not available in IAMService, cannot resolve roles from config.")
		return []string{}, nil
	}
	cfg := s.configManager.GetCurrentConfig()
	if cfg == nil || cfg.IAMConfig.RoleBindings == nil {
		log.Println("IAM: No IAMConfig or RoleBindings found in current config.")
		// Continue to check direct user roles even if no bindings in config
	}

	resolvedRolesMap := make(map[string]struct{})

	// Add roles from RoleBindings
	if cfg != nil && cfg.IAMConfig.RoleBindings != nil {
		for _, rb := range cfg.IAMConfig.RoleBindings {
			if rb.PrincipalType == "user" && rb.PrincipalID == principalID {
				resolvedRolesMap[rb.RoleName] = struct{}{}
			} else if rb.PrincipalType == "serviceaccount" && rb.PrincipalID == principalID {
				// This function is primarily for users, but service account logic is here for completeness
				// though service accounts don't have 'userGroupIDs'.
				resolvedRolesMap[rb.RoleName] = struct{}{}
			} else if rb.PrincipalType == "group" {
				for _, userGroupID := range userGroupIDs { // userGroupIDs is relevant for users
					if rb.PrincipalID == userGroupID {
						resolvedRolesMap[rb.RoleName] = struct{}{}
						break
					}
				}
			}
		}
	}

	// Add directly assigned roles from the iam.User object
	// This part is new, to incorporate direct user roles.
	// We need to determine if the principalID is a user.
	// For now, this function is called in contexts where principalID is a user.
	// If it could be a service account, we'd need to differentiate.
	// Assuming principalID is a User ID for this part:
	if strings.HasPrefix(principalID, "usr-") { // Heuristic to check if it's a user ID
		user, err := s.GetUser(ctx, principalID) // Fetches from cache or store
		if err == nil && user != nil && len(user.RoleNames) > 0 {
			for _, directRoleName := range user.RoleNames {
				resolvedRolesMap[directRoleName] = struct{}{}
			}
		} else if err != nil && !errors.Is(err, ErrUserNotFound) {
			log.Printf("IAM: getResolvedRolesForPrincipal - Error fetching user %s for direct roles: %v", principalID, err)
		}
	}
	// For service accounts, direct roles might be on the APIKey or ServiceAccount struct itself,
	// which is handled differently (e.g., in CheckPermission from APIKey.RoleNames).

	var roles []string
	for roleName := range resolvedRolesMap {
		roles = append(roles, roleName)
	}
	log.Printf("IAM: Resolved roles for principal %s: %v", principalID, roles)
	return roles, nil
}

func (s *Service) GenerateAPIKey(ctx context.Context, userID string, name string, roleNames []string, expiresAt time.Time) (string, *APIKey, error) {
	randomBytes := make([]byte, apiKeyByteLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate random bytes for API key: %w", err)
	}
	rawKey := apiKeyPrefix + hex.EncodeToString(randomBytes)
	hasher := sha256.New()
	hasher.Write([]byte(rawKey))
	hashedKey := hex.EncodeToString(hasher.Sum(nil))
	apiKey := &APIKey{
		ID:        fmt.Sprintf("%s_%s", apiKeyPrefix, uuidShort()),
		HashedKey: hashedKey, UserID: userID, Name: name, RoleNames: roleNames,
		ExpiresAt: expiresAt, CreatedAt: time.Now().UTC(), Revoked: false,
	}
	apiKeyData, err := json.Marshal(apiKey)
	if err != nil {
		return "", nil, fmt.Errorf("marshal API key: %w", err)
	}
	apiKeyRecordKey := "iam/apikeys/" + apiKey.ID
	apiKeyHashIndexKey := "iam/apikeys_by_hash/" + apiKey.HashedKey
	if err = s.store.Set(ctx, apiKeyRecordKey, apiKeyData); err != nil {
		return "", nil, fmt.Errorf("store API key %s: %w", apiKey.ID, err)
	}
	if err = s.store.Set(ctx, apiKeyHashIndexKey, []byte(apiKey.ID)); err != nil {
		s.store.Delete(ctx, apiKeyRecordKey)
		return "", nil, fmt.Errorf("store API key hash index for %s: %w", apiKey.ID, err)
	}
	return rawKey, apiKey, nil
}

func (s *Service) ValidateAPIKey(ctx context.Context, rawKey string) (*APIKey, error) {
	if !strings.HasPrefix(rawKey, apiKeyPrefix) {
		return nil, fmt.Errorf("invalid API key format")
	}
	hasher := sha256.New()
	hasher.Write([]byte(rawKey))
	hashedKeyFromRaw := hex.EncodeToString(hasher.Sum(nil))
	apiKeyIDBytes, err := s.store.Get(ctx, "iam/apikeys_by_hash/"+hashedKeyFromRaw)
	if err != nil {
		return nil, fmt.Errorf("API key not found (hash lookup): %w", err)
	}
	if len(apiKeyIDBytes) == 0 {
		return nil, fmt.Errorf("API key not found (empty ID)")
	}
	apiKeyData, err := s.store.Get(ctx, "iam/apikeys/"+string(apiKeyIDBytes))
	if err != nil {
		return nil, fmt.Errorf("API key not found (record lookup): %w", err)
	}
	var apiKey APIKey
	if json.Unmarshal(apiKeyData, &apiKey) != nil {
		return nil, fmt.Errorf("process API key data")
	}
	if apiKey.HashedKey != hashedKeyFromRaw {
		return nil, fmt.Errorf("API key hash mismatch")
	}
	if apiKey.Revoked {
		return nil, fmt.Errorf("API key %s revoked", apiKey.ID)
	}
	if !apiKey.ExpiresAt.IsZero() && apiKey.ExpiresAt.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("API key %s expired", apiKey.ID)
	}
	return &apiKey, nil
}

func (s *Service) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		ctx := r.Context()
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if strings.HasPrefix(token, apiKeyPrefix) {
				apiKey, err := s.ValidateAPIKey(ctx, token)
				if err == nil && apiKey != nil {
					newCtx := context.WithValue(context.WithValue(context.WithValue(ctx, ContextKeyPrincipalID, apiKey.UserID), ContextKeyAuthMethod, AuthMethodAPIKey), ContextKeyAuthInfo, apiKey)
					next.ServeHTTP(w, r.WithContext(newCtx))
					return
				}
				http.Error(w, "Unauthorized: Invalid API Key", http.StatusUnauthorized)
				return
			} else {
				claims, err := s.ValidateGatewayJWT(token)
				if err == nil && claims != nil {
					newCtx := context.WithValue(context.WithValue(context.WithValue(ctx, ContextKeyPrincipalID, claims.Subject), ContextKeyAuthMethod, AuthMethodJWT), ContextKeyAuthInfo, claims)
					next.ServeHTTP(w, r.WithContext(newCtx))
					return
				}
				http.Error(w, "Unauthorized: Invalid Token", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) AuthzMiddleware(requiredPermission config.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			principalID, ok := ctx.Value(ContextKeyPrincipalID).(string)
			if !ok || principalID == "" {
				http.Error(w, "Forbidden: Auth required", http.StatusForbidden)
				return
			}
			if !s.CheckPermission(ctx, principalID, ctx.Value(ContextKeyAuthInfo), requiredPermission) {
				http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Service) CheckPermission(ctx context.Context, principalID string, authInfo interface{}, requiredPerm config.Permission) bool {
	s.rolesLock.RLock()
	defer s.rolesLock.RUnlock()
	var principalRoleNames []string
	if apiKey, ok := authInfo.(*APIKey); ok {
		principalRoleNames = apiKey.RoleNames
	} else if claims, ok := authInfo.(*GatewayJWTClaims); ok {
		principalRoleNames = claims.Roles
	}

	if len(principalRoleNames) == 0 {
		log.Printf("IAM: CheckPermission - No roles in authInfo for %s. Trying store.", principalID)
		userConfigData, err := s.store.Get(ctx, "iam/users/"+principalID)
		if err == nil && userConfigData != nil {
			var userCfg config.UserConfig
			if json.Unmarshal(userConfigData, &userCfg) == nil {
				resolvedStoreRoles, errResolve := s.getResolvedRolesForPrincipal(ctx, principalID, userCfg.GroupIDs)
				if errResolve != nil {
					log.Printf("IAM: CheckPermission - Error resolving roles from store for %s: %v", principalID, errResolve)
				} else {
					principalRoleNames = resolvedStoreRoles
				}
			} else {
				log.Printf("IAM: CheckPermission - Failed to unmarshal UserConfig for %s.", principalID)
			}
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			log.Printf("IAM: CheckPermission - Failed to get UserConfig for %s: %v", principalID, err)
		}
	}

	if len(principalRoleNames) == 0 {
		log.Printf("IAM: CheckPermission - Principal %s has no roles.", principalID)
		return false
	}
	finalRoles := make(map[string]struct{})
	var uniqueRoles []string
	for _, rName := range principalRoleNames {
		if _, exists := finalRoles[rName]; !exists {
			finalRoles[rName] = struct{}{}
			uniqueRoles = append(uniqueRoles, rName)
		}
	}
	principalRoleNames = uniqueRoles
	for _, roleName := range principalRoleNames {
		role, exists := s.roles[roleName]
		if !exists || role == nil {
			log.Printf("IAM: CheckPermission - Role '%s' for %s not in cached roles or role is nil.", roleName, principalID)
			continue
		}
		for _, rolePerm := range role.Permissions {
			if matchPermission(config.Permission(rolePerm), requiredPerm) {
				return true
			}
		}
	}
	log.Printf("IAM: CheckPermission - Permission '%s' denied for %s (roles: %v)", requiredPerm, principalID, principalRoleNames)
	return false
}

func matchPermission(grantedPerm, requiredPerm config.Permission) bool {
	if grantedPerm == "*:*" || grantedPerm == "*" {
		return true
	}
	if grantedPerm == requiredPerm {
		return true
	}
	grantedParts := strings.SplitN(string(grantedPerm), ":", 2)
	requiredParts := strings.SplitN(string(requiredPerm), ":", 2)

	if len(grantedParts) == 2 && len(requiredParts) == 2 {
		resourceMatch := grantedParts[0] == "*" || grantedParts[0] == requiredParts[0]
		if !resourceMatch {
			return false
		}

		grantedAction := grantedParts[1]
		requiredAction := requiredParts[1]

		if grantedAction == "*" || grantedAction == requiredAction {
			return true
		}

		if strings.HasSuffix(grantedAction, ":*") {
			grantedActionPrefix := strings.TrimSuffix(grantedAction, ":*")
			if strings.HasPrefix(requiredAction, grantedActionPrefix) {
				if grantedActionPrefix == requiredParts[0] && strings.Count(requiredAction, ":") > strings.Count(grantedActionPrefix, ":") {
					return true
				}
				if strings.HasPrefix(requiredAction, strings.TrimSuffix(grantedAction, "*")) {
					return true
				}
			}
		}
		if strings.HasSuffix(grantedAction, "*") {
			if strings.HasPrefix(requiredAction, strings.TrimSuffix(grantedAction, "*")) {
				return true
			}
		}

		return false
	}
	return false
}

func uuidShort() string { return uuid.New().String()[:8] }

func (s *Service) IssueGatewayJWT(userID, email string, oidcGroups []string) (string, error) {
	if len(s.jwtKey) == 0 {
		log.Println("IAM: IssueGatewayJWT - JWT signing key is not loaded. Cannot issue token.")
		return "", fmt.Errorf("JWT signing key not available")
	}
	ctxForRoleResolution := context.Background()
	var resolvedRoles []string
	userConfigData, err := s.store.Get(ctxForRoleResolution, "iam/users/"+userID)
	if err == nil && userConfigData != nil {
		var userCfg config.UserConfig
		if json.Unmarshal(userConfigData, &userCfg) == nil {
			resolvedStoreRoles, errResolve := s.getResolvedRolesForPrincipal(ctxForRoleResolution, userID, userCfg.GroupIDs)
			if errResolve != nil {
				log.Printf("IAM: IssueGatewayJWT - Error resolving roles for %s: %v.", userID, errResolve)
			} else {
				resolvedRoles = resolvedStoreRoles
			}
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		log.Printf("IAM: IssueGatewayJWT - Failed to get UserConfig for %s: %v.", userID, err)
	} else {
		resolvedRoles = []string{"default_user_role"}
	}
	claims := &GatewayJWTClaims{
		UserID: userID, Email: email, Groups: oidcGroups, Roles: resolvedRoles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			Issuer:    "openpons-gateway", Subject: userID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtKey)
}

// CreateRole adds a new role to the system.
func (s *Service) CreateRole(ctx context.Context, role *Role) (*Role, error) {
	if role == nil || role.Name == "" {
		return nil, errors.New("role and role name cannot be empty")
	}

	s.rolesLock.Lock()
	defer s.rolesLock.Unlock()

	if _, exists := s.roles[role.Name]; exists {
		return nil, ErrRoleAlreadyExists
	}

	roleKey := "iam/roles/" + role.Name
	existingData, err := s.store.Get(ctx, roleKey)
	if err == nil && len(existingData) > 0 {
		log.Printf("IAM: CreateRole - Role '%s' exists in store but not in cache. Reporting as already exists.", role.Name)
		return nil, ErrRoleAlreadyExists
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing role in store for '%s': %w", role.Name, err)
	}

	roleData, err := json.Marshal(role)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal role '%s': %w", role.Name, err)
	}

	if err := s.store.Set(ctx, roleKey, roleData); err != nil {
		return nil, fmt.Errorf("failed to store role '%s': %w", role.Name, err)
	}

	s.roles[role.Name] = role

	log.Printf("IAM: Created role '%s'", role.Name)
	return role, nil
}

// ListRoles retrieves all defined roles from the in-memory cache.
func (s *Service) ListRoles(ctx context.Context) ([]*Role, error) {
	s.rolesLock.RLock()
	defer s.rolesLock.RUnlock()

	if len(s.roles) == 0 {
		log.Println("IAM: ListRoles - No roles found in cache.")
		return []*Role{}, nil
	}

	roleList := make([]*Role, 0, len(s.roles))
	for _, role := range s.roles {
		roleList = append(roleList, role)
	}

	log.Printf("IAM: ListRoles - Returning %d roles from cache.", len(roleList))
	return roleList, nil
}

// GetRole retrieves a specific role by its name from the in-memory cache.
func (s *Service) GetRole(ctx context.Context, roleName string) (*Role, error) {
	s.rolesLock.RLock()
	defer s.rolesLock.RUnlock()

	role, exists := s.roles[roleName]
	if !exists {
		log.Printf("IAM: GetRole - Role '%s' not found in cache.", roleName)
		return nil, ErrRoleNotFound
	}
	log.Printf("IAM: GetRole - Found role '%s' in cache.", roleName)
	return role, nil
}

// UpdateRole updates an existing role.
func (s *Service) UpdateRole(ctx context.Context, roleName string, roleUpdate *Role) (*Role, error) {
	if roleUpdate == nil {
		return nil, errors.New("role update data cannot be nil")
	}
	if roleUpdate.Name != "" && roleUpdate.Name != roleName {
		return nil, errors.New("role name in path and body mismatch")
	}

	s.rolesLock.Lock()
	defer s.rolesLock.Unlock()

	existingRole, exists := s.roles[roleName]
	if !exists {
		return nil, ErrRoleNotFound
	}

	if roleUpdate.Description != "" {
		existingRole.Description = roleUpdate.Description
	}
	if roleUpdate.Permissions != nil {
		existingRole.Permissions = roleUpdate.Permissions
	}

	roleKey := "iam/roles/" + roleName
	roleData, err := json.Marshal(existingRole)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated role '%s': %w", roleName, err)
	}

	if err := s.store.Set(ctx, roleKey, roleData); err != nil {
		return nil, fmt.Errorf("failed to store updated role '%s': %w", roleName, err)
	}

	log.Printf("IAM: Updated role '%s'", roleName)
	return existingRole, nil
}

// DeleteRole removes a role from the system.
func (s *Service) DeleteRole(ctx context.Context, roleName string) error {
	s.rolesLock.Lock()
	defer s.rolesLock.Unlock()

	if _, exists := s.roles[roleName]; !exists {
		return ErrRoleNotFound
	}

	roleKey := "iam/roles/" + roleName
	if err := s.store.Delete(ctx, roleKey); err != nil {
		log.Printf("IAM: DeleteRole - Failed to delete role '%s' from store: %v. Will still remove from cache.", roleName, err)
	}

	delete(s.roles, roleName)

	log.Printf("IAM: Deleted role '%s'", roleName)
	return nil
}

// --- Group Management ---

// CreateGroup adds a new group to the system.
func (s *Service) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	if group == nil || group.Name == "" {
		return nil, errors.New("group and group name cannot be empty")
	}

	s.groupsLock.Lock()
	defer s.groupsLock.Unlock()

	for _, existingGroup := range s.groups {
		if existingGroup.Name == group.Name {
			return nil, ErrGroupAlreadyExists
		}
	}

	group.ID = "grp-" + uuid.New().String()
	now := time.Now().UTC()
	group.CreatedAt = now
	group.UpdatedAt = now

	groupKey := "iam/groups/" + group.ID
	groupData, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal group '%s': %w", group.Name, err)
	}

	if err := s.store.Set(ctx, groupKey, groupData); err != nil {
		return nil, fmt.Errorf("failed to store group '%s': %w", group.Name, err)
	}

	s.groups[group.ID] = group

	log.Printf("IAM: Created group '%s' (ID: %s)", group.Name, group.ID)
	return group, nil
}

// ListGroups retrieves groups from the in-memory cache, with filtering and pagination.
func (s *Service) ListGroups(ctx context.Context, opts ListGroupOptions) ([]*Group, int, error) {
	s.groupsLock.RLock()
	defer s.groupsLock.RUnlock()

	if len(s.groups) == 0 {
		log.Println("IAM: ListGroups - No groups found in cache.")
		return []*Group{}, 0, nil
	}

	allMatchingGroups := make([]*Group, 0)
	for _, group := range s.groups {
		// Apply NameFilter (case-insensitive contains)
		if opts.NameFilter != "" {
			if !strings.Contains(strings.ToLower(group.Name), strings.ToLower(opts.NameFilter)) {
				continue // Skip if name doesn't match filter
			}
		}
		allMatchingGroups = append(allMatchingGroups, group)
	}

	totalCount := len(allMatchingGroups)

	// Sort by name for consistent pagination
	sort.SliceStable(allMatchingGroups, func(i, j int) bool {
		return allMatchingGroups[i].Name < allMatchingGroups[j].Name
	})

	// Apply pagination
	start := opts.Offset
	if start < 0 {
		start = 0
	}
	if start >= totalCount {
		return []*Group{}, totalCount, nil // Offset is beyond the number of items
	}

	end := start + opts.Limit
	if end > totalCount {
		end = totalCount
	}
	if opts.Limit <= 0 { // If limit is not positive, return all matching (after offset)
		end = totalCount
	}

	paginatedGroups := allMatchingGroups[start:end]

	log.Printf("IAM: ListGroups - Returning %d groups out of %d matching, from cache.", len(paginatedGroups), totalCount)
	return paginatedGroups, totalCount, nil
}

// GetGroup retrieves a specific group by its ID from the in-memory cache.
func (s *Service) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	s.groupsLock.RLock()
	defer s.groupsLock.RUnlock()

	group, exists := s.groups[groupID]
	if !exists {
		log.Printf("IAM: GetGroup - Group '%s' not found in cache.", groupID)
		return nil, ErrGroupNotFound
	}
	log.Printf("IAM: GetGroup - Found group '%s' (ID: %s) in cache.", group.Name, groupID)
	return group, nil
}

// UpdateGroup updates an existing group.
func (s *Service) UpdateGroup(ctx context.Context, groupID string, groupUpdate *Group) (*Group, error) {
	if groupUpdate == nil {
		return nil, errors.New("group update data cannot be nil")
	}

	s.groupsLock.Lock()
	defer s.groupsLock.Unlock()

	existingGroup, exists := s.groups[groupID]
	if !exists {
		return nil, ErrGroupNotFound
	}

	if groupUpdate.Name != "" && groupUpdate.Name != existingGroup.Name {
		for id, grp := range s.groups {
			if id != groupID && grp.Name == groupUpdate.Name {
				return nil, ErrGroupAlreadyExists
			}
		}
		existingGroup.Name = groupUpdate.Name
	}

	if groupUpdate.MemberIDs != nil {
		existingGroup.MemberIDs = groupUpdate.MemberIDs
	}
	existingGroup.UpdatedAt = time.Now().UTC()

	groupKey := "iam/groups/" + groupID
	groupData, err := json.Marshal(existingGroup)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated group '%s': %w", groupID, err)
	}

	if err := s.store.Set(ctx, groupKey, groupData); err != nil {
		return nil, fmt.Errorf("failed to store updated group '%s': %w", groupID, err)
	}

	log.Printf("IAM: Updated group '%s' (ID: %s)", existingGroup.Name, groupID)
	return existingGroup, nil
}

// DeleteGroup removes a group from the system by its ID.
func (s *Service) DeleteGroup(ctx context.Context, groupID string) error {
	s.groupsLock.Lock()
	defer s.groupsLock.Unlock()

	if _, exists := s.groups[groupID]; !exists {
		return ErrGroupNotFound
	}

	groupKey := "iam/groups/" + groupID
	if err := s.store.Delete(ctx, groupKey); err != nil {
		log.Printf("IAM: DeleteGroup - Failed to delete group '%s' from store: %v. Will still remove from cache.", groupID, err)
	}

	delete(s.groups, groupID)

	log.Printf("IAM: Deleted group (ID: %s)", groupID)
	return nil
}

// ModifyGroupMembers adds or removes members from a group.
func (s *Service) ModifyGroupMembers(ctx context.Context, groupID string, addMemberIDs []string, removeMemberIDs []string) (*Group, error) {
	s.groupsLock.Lock()
	defer s.groupsLock.Unlock()

	existingGroup, exists := s.groups[groupID]
	if !exists {
		return nil, ErrGroupNotFound
	}

	// Process removals first
	if len(removeMemberIDs) > 0 {
		membersToKeep := make([]string, 0, len(existingGroup.MemberIDs))
		removeMap := make(map[string]struct{}, len(removeMemberIDs))
		for _, id := range removeMemberIDs {
			removeMap[id] = struct{}{}
		}
		for _, memberID := range existingGroup.MemberIDs {
			if _, shouldRemove := removeMap[memberID]; !shouldRemove {
				membersToKeep = append(membersToKeep, memberID)
			}
		}
		existingGroup.MemberIDs = membersToKeep
	}

	// Process additions
	if len(addMemberIDs) > 0 {
		currentMembersMap := make(map[string]struct{}, len(existingGroup.MemberIDs))
		for _, memberID := range existingGroup.MemberIDs {
			currentMembersMap[memberID] = struct{}{}
		}
		for _, memberIDToAdd := range addMemberIDs {
			// Validate if memberIDToAdd (user ID) actually exists in the system.
			user, err := s.GetUser(ctx, memberIDToAdd) // GetUser checks cache and store
			if err != nil {
				// If GetUser returns ErrUserNotFound or any other error
				log.Printf("IAM: ModifyGroupMembers - Failed to validate user ID '%s' for adding to group '%s': %v", memberIDToAdd, groupID, err)
				return nil, fmt.Errorf("user to add (ID: %s) not found or error fetching: %w", memberIDToAdd, err)
			}
			if user == nil { // Should be covered by GetUser error handling, but as a safeguard
				log.Printf("IAM: ModifyGroupMembers - User ID '%s' not found for adding to group '%s'.", memberIDToAdd, groupID)
				return nil, fmt.Errorf("user to add (ID: %s) not found", memberIDToAdd)
			}

			if _, alreadyMember := currentMembersMap[memberIDToAdd]; !alreadyMember {
				existingGroup.MemberIDs = append(existingGroup.MemberIDs, memberIDToAdd)
				currentMembersMap[memberIDToAdd] = struct{}{}
			}
		}
	}

	existingGroup.UpdatedAt = time.Now().UTC()

	groupKey := "iam/groups/" + groupID
	groupData, err := json.Marshal(existingGroup)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal group '%s' after modifying members: %w", groupID, err)
	}

	if err := s.store.Set(ctx, groupKey, groupData); err != nil {
		return nil, fmt.Errorf("failed to store group '%s' after modifying members: %w", groupID, err)
	}

	log.Printf("IAM: Modified members for group '%s' (ID: %s)", existingGroup.Name, groupID)
	return existingGroup, nil
}

// --- Role Binding Management ---

// CreateRoleBinding creates a new role binding.
func (s *Service) CreateRoleBinding(ctx context.Context, binding *RoleBinding) (*RoleBinding, error) {
	if binding == nil || binding.PrincipalID == "" || binding.RoleName == "" || binding.PrincipalType == "" {
		return nil, errors.New("principalID, principalType, and roleName are required for a role binding")
	}

	if binding.PrincipalType != "user" && binding.PrincipalType != "group" && binding.PrincipalType != "serviceaccount" {
		return nil, ErrInvalidPrincipalType
	}

	s.rolesLock.RLock()
	_, roleExists := s.roles[binding.RoleName]
	s.rolesLock.RUnlock()
	if !roleExists {
		return nil, ErrRoleNotFound
	}

	// Validate PrincipalID existence
	if binding.PrincipalType == "user" {
		_, err := s.GetUser(ctx, binding.PrincipalID) // GetUser checks cache and store
		if err != nil {
			log.Printf("IAM: CreateRoleBinding - User principal '%s' validation failed: %v", binding.PrincipalID, err)
			if errors.Is(err, ErrUserNotFound) {
				return nil, ErrUserNotFound
			}
			return nil, fmt.Errorf("failed to validate user principal '%s': %w", binding.PrincipalID, err)
		}
	} else if binding.PrincipalType == "group" {
		_, err := s.GetGroup(ctx, binding.PrincipalID) // Assuming GetGroup also checks cache then store
		if err != nil {
			log.Printf("IAM: CreateRoleBinding - Group principal '%s' validation failed: %v", binding.PrincipalID, err)
			if errors.Is(err, ErrGroupNotFound) {
				return nil, ErrGroupNotFound
			}
			return nil, fmt.Errorf("failed to validate group principal '%s': %w", binding.PrincipalID, err)
		}
	} else if binding.PrincipalType == "serviceaccount" {
		_, err := s.GetServiceAccount(ctx, binding.PrincipalID) // GetServiceAccount checks cache and store
		if err != nil {
			log.Printf("IAM: CreateRoleBinding - ServiceAccount principal '%s' validation failed: %v", binding.PrincipalID, err)
			if errors.Is(err, ErrServiceAccountNotFound) {
				return nil, ErrServiceAccountNotFound
			}
			return nil, fmt.Errorf("failed to validate service account principal '%s': %w", binding.PrincipalID, err)
		}
	}
	// Service account validation added above.

	s.roleBindingsLock.Lock()
	defer s.roleBindingsLock.Unlock()

	// Check for duplicate binding (same principal, role, and scope)
	for _, existingBinding := range s.roleBindings {
		if existingBinding.PrincipalID == binding.PrincipalID &&
			existingBinding.PrincipalType == binding.PrincipalType &&
			existingBinding.RoleName == binding.RoleName &&
			existingBinding.Scope.Type == binding.Scope.Type && // Ensure scope comparison is correct
			existingBinding.Scope.Value == binding.Scope.Value {
			return nil, ErrRoleBindingAlreadyExists
		}
	}

	binding.ID = "rb-" + uuid.New().String()
	binding.CreatedAt = time.Now().UTC()

	bindingKey := "iam/rolebindings/" + binding.ID
	bindingData, err := json.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal role binding: %w", err)
	}

	if err := s.store.Set(ctx, bindingKey, bindingData); err != nil {
		return nil, fmt.Errorf("failed to store role binding: %w", err)
	}

	s.roleBindings[binding.ID] = binding
	log.Printf("IAM: Created RoleBinding ID %s for Principal %s (%s) to Role %s", binding.ID, binding.PrincipalID, binding.PrincipalType, binding.RoleName)

	// Trigger a configuration update because role bindings can affect resolved roles.
	if s.configManager != nil {
		if err := s.configManager.ReloadConfig(ctx); err != nil {
			// Log the error but don't fail the CreateRoleBinding operation itself,
			// as the binding is already persisted. The config will update on next poll/restart.
			log.Printf("IAM: CreateRoleBinding - Failed to trigger immediate config reload after creating binding %s: %v", binding.ID, err)
		} else {
			log.Printf("IAM: CreateRoleBinding - Successfully triggered config reload after creating binding %s.", binding.ID)
		}
	}
	return binding, nil
}

// ListRoleBindings retrieves role bindings from the in-memory cache, with filtering and pagination.
func (s *Service) ListRoleBindings(ctx context.Context, opts ListRoleBindingOptions) ([]*RoleBinding, int, error) {
	s.roleBindingsLock.RLock()
	defer s.roleBindingsLock.RUnlock()

	if len(s.roleBindings) == 0 {
		log.Println("IAM: ListRoleBindings - No role bindings found in cache.")
		return []*RoleBinding{}, 0, nil
	}

	allMatchingBindings := make([]*RoleBinding, 0)
	for _, binding := range s.roleBindings {
		// Apply PrincipalIDFilter
		if opts.PrincipalIDFilter != "" && binding.PrincipalID != opts.PrincipalIDFilter {
			continue
		}
		// Apply PrincipalTypeFilter
		if opts.PrincipalTypeFilter != "" && binding.PrincipalType != opts.PrincipalTypeFilter {
			continue
		}
		// Apply RoleNameFilter (exact match for now, could be contains if needed)
		if opts.RoleNameFilter != "" && binding.RoleName != opts.RoleNameFilter {
			continue
		}
		allMatchingBindings = append(allMatchingBindings, binding)
	}

	totalCount := len(allMatchingBindings)

	// Sort by CreatedAt for consistent pagination (or another field like ID)
	sort.SliceStable(allMatchingBindings, func(i, j int) bool {
		return allMatchingBindings[i].CreatedAt.Before(allMatchingBindings[j].CreatedAt)
	})

	// Apply pagination
	start := opts.Offset
	if start < 0 {
		start = 0
	}
	if start >= totalCount {
		return []*RoleBinding{}, totalCount, nil // Offset is beyond the number of items
	}

	end := start + opts.Limit
	if end > totalCount {
		end = totalCount
	}
	if opts.Limit <= 0 { // If limit is not positive, return all matching (after offset)
		end = totalCount
	}

	paginatedBindings := allMatchingBindings[start:end]

	log.Printf("IAM: ListRoleBindings - Returning %d role bindings out of %d matching, from cache.", len(paginatedBindings), totalCount)
	return paginatedBindings, totalCount, nil
}

// GetRoleBinding retrieves a specific role binding by its ID from the in-memory cache.
func (s *Service) GetRoleBinding(ctx context.Context, bindingID string) (*RoleBinding, error) {
	s.roleBindingsLock.RLock()
	defer s.roleBindingsLock.RUnlock()

	binding, exists := s.roleBindings[bindingID]
	if !exists {
		log.Printf("IAM: GetRoleBinding - RoleBinding ID '%s' not found in cache.", bindingID)
		return nil, ErrRoleBindingNotFound
	}
	log.Printf("IAM: GetRoleBinding - Found RoleBinding ID '%s' in cache.", bindingID)
	return binding, nil
}

// DeleteRoleBinding removes a role binding from the system by its ID.
func (s *Service) DeleteRoleBinding(ctx context.Context, bindingID string) error {
	s.roleBindingsLock.Lock()
	defer s.roleBindingsLock.Unlock()

	if _, exists := s.roleBindings[bindingID]; !exists {
		return ErrRoleBindingNotFound
	}

	bindingKey := "iam/rolebindings/" + bindingID
	if err := s.store.Delete(ctx, bindingKey); err != nil {
		log.Printf("IAM: DeleteRoleBinding - Failed to delete binding '%s' from store: %v. Will still remove from cache.", bindingID, err)
	}

	delete(s.roleBindings, bindingID)

	log.Printf("IAM: Deleted RoleBinding (ID: %s)", bindingID)

	// Trigger a configuration update because role bindings can affect resolved roles.
	if s.configManager != nil {
		if err := s.configManager.ReloadConfig(ctx); err != nil {
			// Log the error but don't fail the DeleteRoleBinding operation itself,
			// as the binding is already removed from persistence/cache. Config will update on next poll/restart.
			log.Printf("IAM: DeleteRoleBinding - Failed to trigger immediate config reload after deleting binding %s: %v", bindingID, err)
		} else {
			log.Printf("IAM: DeleteRoleBinding - Successfully triggered config reload after deleting binding %s.", bindingID)
		}
	}
	return nil
}

// UpdateRoleBinding updates an existing role binding.
// For the current iam.RoleBinding structure, there are no mutable fields other than potentially
// re-validating referenced entities or if a hypothetical 'description' or 'expires_at' were added to the binding itself.
// This implementation will assume core fields (PrincipalID, PrincipalType, RoleName, Scope) are immutable.
// If an update to these is required, it should be a delete + create operation.
func (s *Service) UpdateRoleBinding(ctx context.Context, bindingID string, bindingUpdateData *RoleBinding) (*RoleBinding, error) {
	s.roleBindingsLock.Lock()
	defer s.roleBindingsLock.Unlock()

	existingBinding, exists := s.roleBindings[bindingID]
	if !exists {
		return nil, ErrRoleBindingNotFound
	}

	// Check if the update attempts to change immutable fields.
	// For simplicity, we'll assume only non-identifying fields could be updated if they existed.
	// Since RoleBinding has no such fields currently (other than CreatedAt which is set on creation),
	// this update function is effectively a no-op or a re-validation.
	// If bindingUpdateData contains changes to PrincipalID, Type, RoleName, or Scope, we could reject.
	// For now, we'll just log and return the existing binding.
	// A real update might involve updating an "UpdatedAt" timestamp if it existed on RoleBinding.

	// Example: if RoleBinding had a Description field:
	// if bindingUpdateData.Description != "" {
	// 	existingBinding.Description = bindingUpdateData.Description
	// 	changed = true
	// }
	// if changed {
	//   existingBinding.UpdatedAt = time.Now().UTC() // If RoleBinding had UpdatedAt
	//   bindingData, err := json.Marshal(existingBinding)
	//   // ... store ...
	// }

	log.Printf("IAM: UpdateRoleBinding called for ID '%s'. No mutable fields in current RoleBinding structure, returning existing.", bindingID)
	// If there were mutable fields and they were updated, you would persist existingBinding to the store here.
	return existingBinding, nil
}

// RemoveRoleBindingsForPrincipal removes all role bindings associated with a given principal.
func (s *Service) RemoveRoleBindingsForPrincipal(ctx context.Context, principalID string, principalType string) error {
	s.roleBindingsLock.Lock()
	defer s.roleBindingsLock.Unlock()

	bindingsToDelete := []string{}
	for id, binding := range s.roleBindings {
		if binding.PrincipalID == principalID && binding.PrincipalType == principalType {
			bindingsToDelete = append(bindingsToDelete, id)
		}
	}

	if len(bindingsToDelete) == 0 {
		log.Printf("IAM: No role bindings found for principal %s (%s) to remove.", principalID, principalType)
		return nil
	}

	for _, bindingID := range bindingsToDelete {
		bindingKey := "iam/rolebindings/" + bindingID
		if err := s.store.Delete(ctx, bindingKey); err != nil {
			// Log error but continue trying to delete others and from cache
			log.Printf("IAM: Failed to delete role binding '%s' from store for principal %s (%s): %v", bindingID, principalID, principalType, err)
		}
		delete(s.roleBindings, bindingID)
		log.Printf("IAM: Deleted role binding '%s' for principal %s (%s)", bindingID, principalID, principalType)
	}

	log.Printf("IAM: Removed %d role bindings for principal %s (%s)", len(bindingsToDelete), principalID, principalType)
	// TODO: Consider if this should trigger a config update notification if role bindings affect runtime config.
	return nil
}

// --- Service Account Management ---

// CreateServiceAccount creates a new service account.
func (s *Service) CreateServiceAccount(ctx context.Context, sa *ServiceAccount) (*ServiceAccount, error) {
	if sa == nil || sa.Name == "" {
		return nil, errors.New("service account and name cannot be empty")
	}

	s.serviceAccountsLock.Lock()
	defer s.serviceAccountsLock.Unlock()

	// Check for name collision
	for _, existingSA := range s.serviceAccounts {
		if existingSA.Name == sa.Name {
			return nil, ErrServiceAccountAlreadyExists
		}
	}

	sa.ID = "sa-" + uuid.New().String()
	now := time.Now().UTC()
	sa.CreatedAt = now
	sa.UpdatedAt = now
	if sa.Status == "" {
		sa.Status = "active" // Default status
	}

	saKey := "iam/serviceaccounts/" + sa.ID
	saData, err := json.Marshal(sa)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal service account '%s': %w", sa.Name, err)
	}

	if err := s.store.Set(ctx, saKey, saData); err != nil {
		return nil, fmt.Errorf("failed to store service account '%s': %w", sa.Name, err)
	}

	s.serviceAccounts[sa.ID] = sa
	log.Printf("IAM: Created ServiceAccount '%s' (ID: %s)", sa.Name, sa.ID)

	// Trigger a configuration update if service accounts are part of runtime config
	// or influence other configurations derived by ConfigManager.
	if s.configManager != nil {
		if err := s.configManager.ReloadConfig(ctx); err != nil {
			log.Printf("IAM: CreateServiceAccount - Failed to trigger immediate config reload after creating SA %s: %v", sa.ID, err)
		} else {
			log.Printf("IAM: CreateServiceAccount - Successfully triggered config reload after creating SA %s.", sa.ID)
		}
	}
	return sa, nil
}

// ListServiceAccounts retrieves service accounts from the in-memory cache, with filtering and pagination.
func (s *Service) ListServiceAccounts(ctx context.Context, opts ListServiceAccountOptions) ([]*ServiceAccount, int, error) {
	s.serviceAccountsLock.RLock()
	defer s.serviceAccountsLock.RUnlock()

	if len(s.serviceAccounts) == 0 {
		log.Println("IAM: ListServiceAccounts - No service accounts found in cache.")
		return []*ServiceAccount{}, 0, nil
	}

	allMatchingSAs := make([]*ServiceAccount, 0)
	for _, sa := range s.serviceAccounts {
		// Apply NameFilter (case-insensitive contains)
		if opts.NameFilter != "" {
			if !strings.Contains(strings.ToLower(sa.Name), strings.ToLower(opts.NameFilter)) {
				continue
			}
		}
		// Apply StatusFilter (exact match)
		if opts.StatusFilter != "" && sa.Status != opts.StatusFilter {
			continue
		}
		allMatchingSAs = append(allMatchingSAs, sa)
	}

	totalCount := len(allMatchingSAs)

	// Sort by name for consistent pagination
	sort.SliceStable(allMatchingSAs, func(i, j int) bool {
		return allMatchingSAs[i].Name < allMatchingSAs[j].Name
	})

	// Apply pagination
	start := opts.Offset
	if start < 0 {
		start = 0
	}
	if start >= totalCount {
		return []*ServiceAccount{}, totalCount, nil
	}

	end := start + opts.Limit
	if end > totalCount {
		end = totalCount
	}
	if opts.Limit <= 0 { // If limit is not positive, return all matching (after offset)
		end = totalCount
	}

	paginatedSAs := allMatchingSAs[start:end]

	log.Printf("IAM: ListServiceAccounts - Returning %d service accounts out of %d matching, from cache.", len(paginatedSAs), totalCount)
	return paginatedSAs, totalCount, nil
}

// GetServiceAccount retrieves a specific service account by its ID from the in-memory cache.
func (s *Service) GetServiceAccount(ctx context.Context, saID string) (*ServiceAccount, error) {
	s.serviceAccountsLock.RLock()
	defer s.serviceAccountsLock.RUnlock()

	sa, exists := s.serviceAccounts[saID]
	if !exists {
		log.Printf("IAM: GetServiceAccount - ServiceAccount ID '%s' not found in cache.", saID)
		return nil, ErrServiceAccountNotFound
	}
	log.Printf("IAM: GetServiceAccount - Found ServiceAccount ID '%s' in cache.", saID)
	return sa, nil
}

// UpdateServiceAccount updates an existing service account.
func (s *Service) UpdateServiceAccount(ctx context.Context, saID string, saUpdate *ServiceAccount) (*ServiceAccount, error) {
	if saUpdate == nil {
		return nil, errors.New("service account update data cannot be nil")
	}

	s.serviceAccountsLock.Lock()
	defer s.serviceAccountsLock.Unlock()

	existingSA, exists := s.serviceAccounts[saID]
	if !exists {
		return nil, ErrServiceAccountNotFound
	}

	changed := false
	if saUpdate.Name != "" && saUpdate.Name != existingSA.Name {
		// Check for name collision if name is being changed
		for id, sa := range s.serviceAccounts {
			if id != saID && sa.Name == saUpdate.Name {
				return nil, ErrServiceAccountAlreadyExists
			}
		}
		existingSA.Name = saUpdate.Name
		changed = true
	}
	if saUpdate.Description != existingSA.Description { // Allow setting empty description
		existingSA.Description = saUpdate.Description
		changed = true
	}
	if saUpdate.Status != "" && saUpdate.Status != existingSA.Status {
		if saUpdate.Status != "active" && saUpdate.Status != "disabled" {
			return nil, fmt.Errorf("invalid status '%s', must be 'active' or 'disabled'", saUpdate.Status)
		}
		existingSA.Status = saUpdate.Status
		changed = true
	}

	if !changed {
		log.Printf("IAM: UpdateServiceAccount - No changes detected for ServiceAccount ID '%s'.", saID)
		return existingSA, nil // Return existing if no effective changes
	}

	existingSA.UpdatedAt = time.Now().UTC()

	saKey := "iam/serviceaccounts/" + saID
	saData, err := json.Marshal(existingSA)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated service account '%s': %w", saID, err)
	}

	if err := s.store.Set(ctx, saKey, saData); err != nil {
		return nil, fmt.Errorf("failed to store updated service account '%s': %w", saID, err)
	}

	log.Printf("IAM: Updated ServiceAccount '%s' (ID: %s)", existingSA.Name, saID)
	return existingSA, nil
}

// DeleteServiceAccount removes a service account from the system by its ID.
func (s *Service) DeleteServiceAccount(ctx context.Context, saID string) error {
	s.serviceAccountsLock.Lock()
	defer s.serviceAccountsLock.Unlock()

	if _, exists := s.serviceAccounts[saID]; !exists {
		return ErrServiceAccountNotFound
	}

	saKey := "iam/serviceaccounts/" + saID
	if err := s.store.Delete(ctx, saKey); err != nil {
		log.Printf("IAM: DeleteServiceAccount - Failed to delete service account '%s' from store: %v. Will still remove from cache.", saID, err)
		// Consider if this should return an error and not remove from cache if store fails.
	}

	delete(s.serviceAccounts, saID)

	log.Printf("IAM: Deleted ServiceAccount (ID: %s) from cache and store.", saID)

	// Implications:
	// 1. Remove RoleBindings associated with this service account
	if err := s.RemoveRoleBindingsForPrincipal(ctx, saID, "serviceaccount"); err != nil {
		// Log the error but consider the SA deletion successful if the main entity is gone.
		// Depending on policy, this could be a hard failure.
		log.Printf("IAM: DeleteServiceAccount - Failed to remove role bindings for SA ID '%s': %v. SA still considered deleted.", saID, err)
	} else {
		log.Printf("IAM: DeleteServiceAccount - Successfully removed role bindings for SA ID '%s'.", saID)
	}

	// 2. Delete API keys associated with this service account
	// Assuming APIKey.UserID can store a ServiceAccount ID.
	if err := s.deleteAPIKeysForServiceAccount(ctx, saID); err != nil {
		log.Printf("IAM: DeleteServiceAccount - Failed to delete API keys for SA ID '%s': %v. SA still considered deleted.", saID, err)
	} else {
		log.Printf("IAM: DeleteServiceAccount - Successfully deleted API keys for SA ID '%s'.", saID)
	}

	// 3. Trigger a configuration update
	if s.configManager != nil {
		if err := s.configManager.ReloadConfig(ctx); err != nil {
			log.Printf("IAM: DeleteServiceAccount - Failed to trigger immediate config reload after deleting SA %s: %v", saID, err)
		} else {
			log.Printf("IAM: DeleteServiceAccount - Successfully triggered config reload after deleting SA %s.", saID)
		}
	}

	return nil
}

// deleteAPIKeysForServiceAccount removes all API keys associated with a specific service account ID.
// This assumes APIKey.UserID field is used to store the ServiceAccount ID for SA-owned keys.
func (s *Service) deleteAPIKeysForServiceAccount(ctx context.Context, serviceAccountID string) error {
	log.Printf("IAM: Attempting to delete API keys for ServiceAccount ID '%s'", serviceAccountID)
	allAPIKeyData, err := s.store.List(ctx, "iam/apikeys/") // Lists all API key records
	if err != nil {
		return fmt.Errorf("failed to list API key records from store for service account cleanup: %w", err)
	}

	var keysDeletedCount int
	for _, apiKeyBytes := range allAPIKeyData {
		var apiKey APIKey
		if errUnmarshal := json.Unmarshal(apiKeyBytes, &apiKey); errUnmarshal == nil {
			// Assuming UserID field in APIKey struct is used for ServiceAccountID for SA keys
			if apiKey.UserID == serviceAccountID {
				if errDel := s.DeleteAPIKey(ctx, apiKey.ID); errDel != nil {
					log.Printf("IAM: deleteAPIKeysForServiceAccount - Failed to delete API key '%s' for SA '%s': %v", apiKey.ID, serviceAccountID, errDel)
					// Continue trying to delete other keys
				} else {
					keysDeletedCount++
				}
			}
		} else {
			log.Printf("IAM: deleteAPIKeysForServiceAccount - Failed to unmarshal API key data during cleanup for SA '%s': %v", serviceAccountID, errUnmarshal)
		}
	}
	if keysDeletedCount > 0 {
		log.Printf("IAM: Deleted %d API keys for ServiceAccount ID '%s'", keysDeletedCount, serviceAccountID)
	}
	return nil
}

// --- User Management ---

// CreateUser creates a new user in the system.
// This is for direct admin creation, distinct from OIDC provisioning.
// The iam.User struct currently supports ID, Email, Status, CreatedAt, UpdatedAt.
// DisplayName and GroupIDs are part of config.UserConfig and managed via OIDC or group API.
func (s *Service) CreateUser(ctx context.Context, user *User) (*User, error) {
	if user == nil || user.Email == "" {
		return nil, errors.New("user and email cannot be empty")
	}

	// Validate email format
	if _, err := mail.ParseAddress(user.Email); err != nil {
		log.Printf("IAM: CreateUser - Invalid email format for '%s': %v", user.Email, err)
		return nil, fmt.Errorf("invalid email format: %w", err)
	}

	s.usersLock.Lock()
	defer s.usersLock.Unlock()

	// Check if user with this email already exists (via store index)
	emailIndexKey := "iam/users_by_email/" + user.Email
	existingUserIDBytes, err := s.store.Get(ctx, emailIndexKey)
	if err == nil && len(existingUserIDBytes) > 0 {
		existingUserID := string(existingUserIDBytes)
		if _, cacheExists := s.users[existingUserID]; cacheExists {
			return nil, ErrUserAlreadyExists
		}
		// Check actual user record in store to be sure
		userRecordKey := "iam/users/" + existingUserID
		if _, storeErr := s.store.Get(ctx, userRecordKey); storeErr == nil {
			// User record exists in store, load to cache and return error
			// This handles cases where cache might be out of sync
			var existingUser User
			userData, _ := s.store.Get(ctx, userRecordKey) // Error already checked
			if json.Unmarshal(userData, &existingUser) == nil {
				s.users[existingUser.ID] = &existingUser
			}
			log.Printf("IAM: CreateUser - User with email '%s' (ID: %s) already exists in store.", user.Email, existingUserID)
			return nil, ErrUserAlreadyExists
		} else if !errors.Is(storeErr, store.ErrNotFound) {
			// Error looking up user record, but email index exists. Problematic state.
			log.Printf("IAM: CreateUser - Error looking up user record for existing email index '%s': %v", user.Email, storeErr)
			return nil, fmt.Errorf("inconsistent data for user email '%s'", user.Email)
		}
		// If user record not found by ID despite email index, proceed to create, but log warning.
		log.Printf("IAM: CreateUser - Email index for '%s' exists (ID: %s) but user record not found. Proceeding with new user creation.", user.Email, existingUserID)
		// Optionally, delete the orphaned email index entry here.
		// s.store.Delete(ctx, emailIndexKey)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("failed to check email index for user '%s': %w", user.Email, err)
	}
	// If we reach here, email is considered available for a new user.

	newUser := &User{ // Create a new User instance to ensure only allowed fields are set
		ID:    "usr-" + uuid.New().String(),
		Email: user.Email,
	}
	now := time.Now().UTC()
	newUser.CreatedAt = now
	newUser.UpdatedAt = now

	if user.Status != "" {
		if user.Status != "active" && user.Status != "disabled" {
			return nil, fmt.Errorf("invalid status '%s', must be 'active' or 'disabled'", user.Status)
		}
		newUser.Status = user.Status
	} else {
		newUser.Status = "active" // Default status
	}

	if len(user.RoleNames) > 0 {
		s.rolesLock.RLock()
		for _, roleName := range user.RoleNames {
			if _, exists := s.roles[roleName]; !exists {
				s.rolesLock.RUnlock()
				return nil, fmt.Errorf("role '%s' not found, cannot assign to user", roleName)
			}
		}
		s.rolesLock.RUnlock()
		newUser.RoleNames = user.RoleNames
	} else {
		newUser.RoleNames = []string{} // Ensure it's an empty slice, not nil
	}

	userKey := "iam/users/" + newUser.ID
	userData, err := json.Marshal(newUser)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user '%s': %w", newUser.Email, err)
	}

	if err := s.store.Set(ctx, userKey, userData); err != nil {
		return nil, fmt.Errorf("failed to store user '%s': %w", newUser.Email, err)
	}
	// Store email index
	if err := s.store.Set(ctx, emailIndexKey, []byte(newUser.ID)); err != nil {
		// Attempt to rollback user creation if email index fails
		s.store.Delete(ctx, userKey)
		return nil, fmt.Errorf("failed to store email index for user '%s': %w", newUser.Email, err)
	}

	s.users[newUser.ID] = newUser // Add to cache
	log.Printf("IAM: Created User '%s' (ID: %s)", newUser.Email, newUser.ID)
	return newUser, nil
}

// ListUsers retrieves users from the in-memory cache, with filtering and pagination.
// Note: This currently lists from the cache. A production system might list from the store
// or ensure the cache is consistently populated from the store.
func (s *Service) ListUsers(ctx context.Context, opts ListUserOptions) ([]*User, int, error) {
	s.usersLock.RLock()
	defer s.usersLock.RUnlock()

	if len(s.users) == 0 {
		log.Println("IAM: ListUsers - No users found in cache.")
		return []*User{}, 0, nil
	}

	allMatchingUsers := make([]*User, 0)
	for _, user := range s.users {
		// Apply StatusFilter (exact match)
		if opts.StatusFilter != "" && user.Status != opts.StatusFilter {
			continue
		}
		// Apply EmailContainsFilter (case-insensitive contains)
		if opts.EmailContainsFilter != "" {
			if !strings.Contains(strings.ToLower(user.Email), strings.ToLower(opts.EmailContainsFilter)) {
				continue
			}
		}
		allMatchingUsers = append(allMatchingUsers, user)
	}

	totalCount := len(allMatchingUsers)

	// Sort by email for consistent pagination
	sort.SliceStable(allMatchingUsers, func(i, j int) bool {
		return allMatchingUsers[i].Email < allMatchingUsers[j].Email
	})

	// Apply pagination
	start := opts.Offset
	if start < 0 {
		start = 0
	}
	if start >= totalCount {
		return []*User{}, totalCount, nil
	}

	end := start + opts.Limit
	if end > totalCount {
		end = totalCount
	}
	if opts.Limit <= 0 { // If limit is not positive, return all matching (after offset)
		end = totalCount
	}

	paginatedUsers := allMatchingUsers[start:end]

	log.Printf("IAM: ListUsers - Returning %d users out of %d matching, from cache.", len(paginatedUsers), totalCount)
	return paginatedUsers, totalCount, nil
}

// GetUser retrieves a specific user by their ID.
// It checks the cache first, then falls back to the store.
func (s *Service) GetUser(ctx context.Context, userID string) (*User, error) {
	s.usersLock.RLock()
	user, exists := s.users[userID]
	s.usersLock.RUnlock()

	if exists {
		log.Printf("IAM: GetUser - Found User ID '%s' in cache.", userID)
		return user, nil
	}

	// If not in cache, try to load from store
	log.Printf("IAM: GetUser - User ID '%s' not in cache, attempting to load from store.", userID)
	userKey := "iam/users/" + userID
	userData, err := s.store.Get(ctx, userKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Printf("IAM: GetUser - User ID '%s' not found in store.", userID)
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user '%s' from store: %w", userID, err)
	}

	var loadedUser User
	if err := json.Unmarshal(userData, &loadedUser); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user data for ID '%s': %w", userID, err)
	}

	// Add to cache after loading from store
	s.usersLock.Lock()
	s.users[loadedUser.ID] = &loadedUser
	s.usersLock.Unlock()

	log.Printf("IAM: GetUser - Loaded User ID '%s' from store into cache.", loadedUser.ID)
	return &loadedUser, nil
}

// UpdateUser updates an existing user's mutable fields (e.g., Status).
// Email is treated as an identifier and is not updatable via this method.
func (s *Service) UpdateUser(ctx context.Context, userID string, userUpdate *User) (*User, error) {
	if userUpdate == nil {
		return nil, errors.New("user update data cannot be nil")
	}

	s.usersLock.Lock()
	defer s.usersLock.Unlock()

	existingUser, exists := s.users[userID]
	if !exists {
		// Try to load from store if not in cache
		userKey := "iam/users/" + userID
		userData, err := s.store.Get(ctx, userKey)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrUserNotFound
			}
			return nil, fmt.Errorf("failed to get user '%s' from store for update: %w", userID, err)
		}
		var loadedUser User
		if err := json.Unmarshal(userData, &loadedUser); err != nil {
			return nil, fmt.Errorf("failed to unmarshal user data for ID '%s' for update: %w", userID, err)
		}
		existingUser = &loadedUser
		s.users[userID] = existingUser // Add to cache
	}

	changed := false
	if userUpdate.Email != "" && userUpdate.Email != existingUser.Email {
		// Disallow email change via this method for simplicity.
		// Email change often requires verification and impacts login.
		// If email change is needed, it might be a separate, more complex flow.
		return nil, errors.New("user email cannot be changed via update")
	}

	if userUpdate.Status != "" && userUpdate.Status != existingUser.Status {
		if userUpdate.Status != "active" && userUpdate.Status != "disabled" {
			return nil, fmt.Errorf("invalid status '%s', must be 'active' or 'disabled'", userUpdate.Status)
		}
		existingUser.Status = userUpdate.Status
		changed = true
	}

	// Handle RoleNames update
	// If userUpdate.RoleNames is nil, it means the client did not intend to update roles.
	// If userUpdate.RoleNames is an empty slice, it means clear existing direct roles.
	// If userUpdate.RoleNames has items, set these as the new direct roles.
	if userUpdate.RoleNames != nil {
		s.rolesLock.RLock()
		for _, roleName := range userUpdate.RoleNames {
			if _, exists := s.roles[roleName]; !exists {
				s.rolesLock.RUnlock()
				return nil, fmt.Errorf("role '%s' not found, cannot assign to user", roleName)
			}
		}
		s.rolesLock.RUnlock()
		existingUser.RoleNames = userUpdate.RoleNames
		changed = true
	}

	if !changed {
		log.Printf("IAM: UpdateUser - No changes detected for User ID '%s'.", userID)
		return existingUser, nil
	}

	existingUser.UpdatedAt = time.Now().UTC()

	userKey := "iam/users/" + userID
	userData, err := json.Marshal(existingUser)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated user '%s': %w", userID, err)
	}

	if err := s.store.Set(ctx, userKey, userData); err != nil {
		return nil, fmt.Errorf("failed to store updated user '%s': %w", userID, err)
	}

	log.Printf("IAM: Updated User '%s' (ID: %s)", existingUser.Email, userID)
	return existingUser, nil
}

// DeleteUser removes a user from the system by their ID.
// It also removes the user's email index.
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	s.usersLock.Lock() // Full lock for multi-step operation (cache + store + index)
	defer s.usersLock.Unlock()

	user, exists := s.users[userID]
	if !exists {
		// If not in cache, try to load from store to get email for index deletion
		userKey := "iam/users/" + userID
		userData, err := s.store.Get(ctx, userKey)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrUserNotFound
			}
			return fmt.Errorf("failed to get user '%s' from store for deletion: %w", userID, err)
		}
		var loadedUser User
		if err := json.Unmarshal(userData, &loadedUser); err != nil {
			return fmt.Errorf("failed to unmarshal user data for ID '%s' for deletion: %w", userID, err)
		}
		user = &loadedUser
		// No need to add to cache if we are about to delete
	}

	if user == nil { // Should not happen if logic above is correct
		return ErrUserNotFound
	}
	userEmail := user.Email // Get email before deleting from cache

	// Delete main user record
	userKey := "iam/users/" + userID
	if err := s.store.Delete(ctx, userKey); err != nil {
		// Log error but proceed to attempt cache and index cleanup
		log.Printf("IAM: DeleteUser - Failed to delete user '%s' from store: %v. Proceeding with cache/index cleanup.", userID, err)
	}

	// Delete email index
	if userEmail != "" {
		emailIndexKey := "iam/users_by_email/" + userEmail
		if err := s.store.Delete(ctx, emailIndexKey); err != nil {
			log.Printf("IAM: DeleteUser - Failed to delete email index for user '%s' (email: %s): %v.", userID, userEmail, err)
		}
	} else {
		log.Printf("IAM: DeleteUser - User '%s' had no email, skipping email index deletion.", userID)
	}

	// Delete from cache
	delete(s.users, userID)

	log.Printf("IAM: Deleted User (ID: %s, Email: %s)", userID, userEmail)
	// TODO: Consider implications for API keys, role bindings associated with this user.
	// These might need to be cleaned up or handled (e.g., orphaned or automatically deleted).

	// 1. Remove role bindings associated with this user
	if err := s.RemoveRoleBindingsForPrincipal(ctx, userID, "user"); err != nil {
		// Log error but continue with deletion. Depending on policy, this could be a hard failure.
		log.Printf("IAM: DeleteUser - Failed to remove role bindings for user '%s': %v. Proceeding with user deletion.", userID, err)
	}

	// 2. Delete/invalidate API keys for the user
	if err := s.deleteAPIKeysForUser(ctx, userID); err != nil {
		log.Printf("IAM: DeleteUser - Failed to delete API keys for user '%s': %v. Proceeding with user deletion.", userID, err)
	}

	// 3. Remove user from all groups they are a member of
	if err := s.removeUserFromAllGroups(ctx, userID); err != nil {
		log.Printf("IAM: DeleteUser - Failed to remove user '%s' from all groups: %v. Proceeding with user deletion.", userID, err)
	}

	// Notify config manager if applicable (after all cleanup attempts)
	// if s.configManager != nil {
	// 	s.configManager.NotifyUserDeleted(ctx, userID)
	// }
	log.Printf("IAM: Successfully deleted user (ID: %s, Email: %s) and associated entities.", userID, userEmail)
	return nil
}

// deleteAPIKeysForUser removes all API keys associated with a specific user ID.
func (s *Service) deleteAPIKeysForUser(ctx context.Context, userID string) error {
	// This method needs to list all API keys, filter by UserID, then delete each one.
	// The DeleteAPIKey method already handles deleting a single key and its hash index.
	log.Printf("IAM: Attempting to delete API keys for user ID '%s'", userID)
	allAPIKeyData, err := s.store.List(ctx, "iam/apikeys/")
	if err != nil {
		return fmt.Errorf("failed to list API key records from store for user cleanup: %w", err)
	}

	var keysDeletedCount int
	for _, apiKeyBytes := range allAPIKeyData {
		var apiKey APIKey
		if err := json.Unmarshal(apiKeyBytes, &apiKey); err == nil {
			if apiKey.UserID == userID {
				if errDel := s.DeleteAPIKey(ctx, apiKey.ID); errDel != nil {
					log.Printf("IAM: deleteAPIKeysForUser - Failed to delete API key '%s' for user '%s': %v", apiKey.ID, userID, errDel)
					// Continue trying to delete other keys
				} else {
					keysDeletedCount++
				}
			}
		} else {
			log.Printf("IAM: deleteAPIKeysForUser - Failed to unmarshal API key data during cleanup for user '%s': %v", userID, err)
		}
	}
	if keysDeletedCount > 0 {
		log.Printf("IAM: Deleted %d API keys for user ID '%s'", keysDeletedCount, userID)
	}
	return nil
}

// removeUserFromAllGroups removes a user from all groups they are a member of.
func (s *Service) removeUserFromAllGroups(ctx context.Context, userID string) error {
	s.groupsLock.Lock() // Need to lock groups for modification
	defer s.groupsLock.Unlock()

	log.Printf("IAM: Attempting to remove user ID '%s' from all groups", userID)
	var groupsModifiedCount int
	for groupID, group := range s.groups {
		memberFound := false
		updatedMemberIDs := make([]string, 0, len(group.MemberIDs))
		for _, memberID := range group.MemberIDs {
			if memberID == userID {
				memberFound = true
			} else {
				updatedMemberIDs = append(updatedMemberIDs, memberID)
			}
		}

		if memberFound {
			group.MemberIDs = updatedMemberIDs
			group.UpdatedAt = time.Now().UTC()
			groupKey := "iam/groups/" + groupID
			groupData, err := json.Marshal(group)
			if err != nil {
				log.Printf("IAM: removeUserFromAllGroups - Failed to marshal group '%s' (ID: %s): %v", group.Name, groupID, err)
				continue // Skip this group, try others
			}
			if err := s.store.Set(ctx, groupKey, groupData); err != nil {
				log.Printf("IAM: removeUserFromAllGroups - Failed to store updated group '%s' (ID: %s): %v", group.Name, groupID, err)
				// Potentially revert in-memory change to group.MemberIDs if store fails, or handle consistency.
				// For now, log and continue.
			} else {
				groupsModifiedCount++
			}
		}
	}
	if groupsModifiedCount > 0 {
		log.Printf("IAM: Removed user ID '%s' from %d groups", userID, groupsModifiedCount)
	}
	return nil
}

// --- API Key Management ---

// ListUserAPIKeys retrieves all API keys associated with a specific user.
// This implementation lists all API key records from the store and filters them.
// For a large number of keys, a more optimized store query or indexing might be needed.
func (s *Service) ListUserAPIKeys(ctx context.Context, userID string) ([]*APIKey, error) {
	// First, ensure the user exists to avoid listing keys for a non-existent user.
	_, err := s.GetUser(ctx, userID) // GetUser handles cache/store lookup
	if err != nil {
		return nil, err // Returns ErrUserNotFound if user doesn't exist
	}

	allAPIKeyData, err := s.store.List(ctx, "iam/apikeys/")
	if err != nil {
		return nil, fmt.Errorf("failed to list API key records from store: %w", err)
	}

	userAPIKeys := make([]*APIKey, 0)
	for _, apiKeyBytes := range allAPIKeyData {
		var apiKey APIKey
		if err := json.Unmarshal(apiKeyBytes, &apiKey); err == nil {
			if apiKey.UserID == userID {
				// For security, ensure HashedKey is not part of the returned object here
				// if this method is used to return data externally.
				// However, since this is an internal service method, returning the full struct is okay.
				// The HTTP handler will be responsible for filtering sensitive fields.
				userAPIKeys = append(userAPIKeys, &apiKey)
			}
		} else {
			log.Printf("IAM: ListUserAPIKeys - Failed to unmarshal API key data: %v", err)
			// Optionally skip this key or return an error for data corruption
		}
	}

	log.Printf("IAM: ListUserAPIKeys - Found %d API keys for User ID '%s'", len(userAPIKeys), userID)
	return userAPIKeys, nil
}

// DeleteAPIKey removes an API key from the system by its ID.
// This involves deleting the main API key record and its hash index.
func (s *Service) DeleteAPIKey(ctx context.Context, apiKeyID string) error {
	apiKeyRecordKey := "iam/apikeys/" + apiKeyID

	// First, get the API key record to retrieve its HashedKey for index deletion.
	apiKeyData, err := s.store.Get(ctx, apiKeyRecordKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrAPIKeyNotFound
		}
		return fmt.Errorf("failed to get API key '%s' for deletion: %w", apiKeyID, err)
	}

	var apiKey APIKey
	if err := json.Unmarshal(apiKeyData, &apiKey); err != nil {
		return fmt.Errorf("failed to unmarshal API key data for '%s': %w", apiKeyID, err)
	}

	// Delete the main API key record.
	if err := s.store.Delete(ctx, apiKeyRecordKey); err != nil {
		// Log error but proceed to attempt hash index deletion.
		log.Printf("IAM: DeleteAPIKey - Failed to delete API key record '%s' from store: %v. Proceeding with hash index cleanup.", apiKeyID, err)
	}

	// Delete the hash index.
	if apiKey.HashedKey != "" {
		apiKeyHashIndexKey := "iam/apikeys_by_hash/" + apiKey.HashedKey
		if err := s.store.Delete(ctx, apiKeyHashIndexKey); err != nil {
			log.Printf("IAM: DeleteAPIKey - Failed to delete API key hash index for '%s' (hash: %s): %v.", apiKeyID, apiKey.HashedKey, err)
			// This might leave an orphaned hash index, but the primary record is gone.
		}
	} else {
		log.Printf("IAM: DeleteAPIKey - API key '%s' had no HashedKey, skipping hash index deletion.", apiKeyID)
	}

	log.Printf("IAM: Deleted APIKey (ID: %s)", apiKeyID)
	// Note: This does not remove the key from any in-memory cache of validated keys if one exists.
	// The current ValidateAPIKey always fetches from store, so cache invalidation is not an immediate issue here.
	return nil
}

// TODO: Consider if API keys for Service Accounts need separate management or use UserID field with SA's ID.

func (s *Service) ValidateGatewayJWT(tokenString string) (*GatewayJWTClaims, error) {
	if len(s.jwtKey) == 0 {
		log.Println("IAM: ValidateGatewayJWT - JWT signing key is not loaded. Cannot validate token.")
		return nil, fmt.Errorf("JWT signing key not available for validation")
	}
	claims := &GatewayJWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected JWT signing method: %v", token.Header["alg"])
		}
		return s.jwtKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT")
	}
	if claims.Issuer != "openpons-gateway" {
		return nil, fmt.Errorf("invalid JWT issuer: %s", claims.Issuer)
	}
	return claims, nil
}
