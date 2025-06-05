package iam

import (
	"time"
	// "github.com/openpons/gateway/internal/config" // If reusing or referencing config types
)

// User represents a user in the IAM system.
type User struct {
	ID        string    `json:"id" yaml:"id"` // UUID
	Email     string    `json:"email" yaml:"email"`
	Status    string    `json:"status" yaml:"status"`                             // e.g., active, disabled
	RoleNames []string  `json:"role_names,omitempty" yaml:"role_names,omitempty"` // Direct roles assigned to the user
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
	// Additional fields: display_name, last_login, etc.
}

// Group represents a collection of users.
type Group struct {
	ID        string    `json:"id" yaml:"id"` // UUID
	Name      string    `json:"name" yaml:"name"`
	MemberIDs []string  `json:"member_ids,omitempty" yaml:"member_ids,omitempty"` // List of User IDs
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// ListGroupOptions defines parameters for listing groups.
type ListGroupOptions struct {
	Limit      int
	Offset     int
	NameFilter string // Filter by group name (e.g., contains)
	// Add other filter fields as needed, e.g., UserID (to find groups a user is in)
}

// ListRoleBindingOptions defines parameters for listing role bindings.
type ListRoleBindingOptions struct {
	Limit               int
	Offset              int
	PrincipalIDFilter   string
	PrincipalTypeFilter string // "user", "group", "serviceaccount"
	RoleNameFilter      string
}

// ListServiceAccountOptions defines parameters for listing service accounts.
type ListServiceAccountOptions struct {
	Limit        int
	Offset       int
	NameFilter   string // Filter by name (e.g., contains)
	StatusFilter string // Filter by status (e.g., "active", "disabled")
}

// ListUserOptions defines parameters for listing users.
type ListUserOptions struct {
	Limit               int
	Offset              int
	StatusFilter        string // Filter by status (e.g., "active", "disabled")
	EmailContainsFilter string // Filter by email (e.g., contains substring)
}

// Role defines a set of permissions.
type Role struct {
	Name        string       `json:"name" yaml:"name"` // Unique role name (e.g., "admin", "model_operator")
	Permissions []Permission `json:"permissions" yaml:"permissions"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
	// BuiltIn bool `json:"built_in,omitempty" yaml:"built_in,omitempty"` // To distinguish system roles
}

// Permission is a string representing an action on a resource.
// Format: "resource_type:action[:instance_qualifier]"
// Examples: "models:read", "routes:write", "proxy:invoke:model_xyz", "*:*" (superuser)
type Permission string

// RoleBinding links a principal (User or Group) to a Role within a specific scope.
type RoleBinding struct {
	ID            string    `json:"id" yaml:"id"`                           // UUID
	PrincipalType string    `json:"principal_type" yaml:"principal_type"`   // "user" or "group"
	PrincipalID   string    `json:"principal_id" yaml:"principal_id"`       // User.ID or Group.ID
	RoleName      string    `json:"role_name" yaml:"role_name"`             // Role.Name
	Scope         Scope     `json:"scope,omitempty" yaml:"scope,omitempty"` // Optional: for resource-specific roles
	CreatedAt     time.Time `json:"created_at" yaml:"created_at"`
}

// Scope defines the context for a RoleBinding (e.g., global, specific project/route).
type Scope struct {
	Type  string `json:"type" yaml:"type"`                       // e.g., "global", "project", "route_id"
	Value string `json:"value,omitempty" yaml:"value,omitempty"` // ID of the resource if not global
}

// APIKey represents an API key for programmatic access.
type APIKey struct {
	ID         string    `json:"id"`                   // Prefix + hash, or just a unique ID
	HashedKey  string    `json:"hashed_key"`           // The securely hashed key for storage (removed json:"-")
	UserID     string    `json:"user_id"`              // User this key belongs to
	Name       string    `json:"name,omitempty"`       // Optional user-friendly name for the key
	RoleNames  []string  `json:"role_names,omitempty"` // Optional roles directly associated with this key
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	Revoked    bool      `json:"revoked"`
}

// ServiceAccount represents a non-human principal for programmatic access.
// Could be an alternative or complement to user-bound API keys.
type ServiceAccount struct {
	ID          string    `json:"id" yaml:"id"`
	Name        string    `json:"name" yaml:"name"`
	Description string    `json:"description,omitempty" yaml:"description,omitempty"`
	Status      string    `json:"status" yaml:"status"` // active, disabled
	CreatedAt   time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" yaml:"updated_at"`
}

// These types are very similar to those in config.IAMConfig.
// Depending on implementation, they might be merged or config.IAMConfig might use these directly.
// For now, keeping them separate to represent stored entities vs. configuration snapshot entities.
