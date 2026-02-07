package model

import "time"

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// Token represents a bearer token record stored for validation and revocation.
type Token struct {
	Token     string    `bson:"token"`
	UserID    string    `bson:"user_id"`
	Type      string    `bson:"type"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}
