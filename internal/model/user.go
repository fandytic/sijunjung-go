package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AuthProvider represents the authentication provider.
type AuthProvider string

const (
	AuthProviderLocal    AuthProvider = "local"
	AuthProviderGoogle   AuthProvider = "google"
	AuthProviderFacebook AuthProvider = "facebook"
)

// UserRole represents the access level of a user.
type UserRole string

const (
	RoleSuperAdmin UserRole = "super_admin"
	RoleAdmin      UserRole = "admin"
	RoleMerchant   UserRole = "merchant"
	RoleMitra      UserRole = "mitra"
	RoleUser       UserRole = "user"
)

// IsValid checks whether the role is a recognized value.
func (r UserRole) IsValid() bool {
	switch r {
	case RoleSuperAdmin, RoleAdmin, RoleMerchant, RoleMitra, RoleUser:
		return true
	}
	return false
}

// User represents an authenticated system user.
type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	FullName     string             `bson:"full_name" json:"full_name"`
	Email        string             `bson:"email" json:"email"`
	PasswordHash string             `bson:"password_hash" json:"-"`
	Role         UserRole           `bson:"role" json:"role"`
	AuthProvider AuthProvider       `bson:"auth_provider" json:"auth_provider"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
}
