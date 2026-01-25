package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// OTP represents a one-time password for email verification.
type OTP struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    string             `bson:"user_id" json:"user_id"`
	Email     string             `bson:"email" json:"email"`
	Code      string             `bson:"code" json:"-"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	Verified  bool               `bson:"verified" json:"verified"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// VerifyOTPRequest defines payload for OTP verification.
// @Description Request body for OTP verification
type VerifyOTPRequest struct {
	Email string `json:"email" example:"sijunjunggo@gmail.com"`
	Code  string `json:"code" example:"5318"`
}

// ResendOTPRequest defines payload for resending OTP.
// @Description Request body for resending OTP
type ResendOTPRequest struct {
	Email string `json:"email" example:"sijunjunggo@gmail.com"`
}
