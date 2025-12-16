package model

import "time"

// Token represents a bearer token record stored for validation and revocation.
type Token struct {
	Token     string    `bson:"token"`
	UserID    string    `bson:"user_id"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}
