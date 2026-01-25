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

// User represents an authenticated system user.
type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	FullName     string             `bson:"full_name" json:"full_name"`
	Email        string             `bson:"email" json:"email"`
	PasswordHash string             `bson:"password_hash" json:"-"`
	AuthProvider AuthProvider       `bson:"auth_provider" json:"auth_provider"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
}
