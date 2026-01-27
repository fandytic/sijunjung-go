package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// OTP represents a one-time password for email/phone verification.
type OTP struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    string             `bson:"user_id" json:"user_id"`
	Email     string             `bson:"email,omitempty" json:"email,omitempty"`
	Phone     string             `bson:"phone,omitempty" json:"phone,omitempty"`
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

// SendWhatsAppOTPRequest defines payload for sending OTP via WhatsApp.
// @Description Request body for sending OTP via WhatsApp
type SendWhatsAppOTPRequest struct {
	Phone string `json:"phone" example:"628123456789"`
}

// VerifyWhatsAppOTPRequest defines payload for verifying OTP sent via WhatsApp.
// @Description Request body for verifying WhatsApp OTP
type VerifyWhatsAppOTPRequest struct {
	Phone string `json:"phone" example:"628123456789"`
	Code  string `json:"code" example:"5318"`
}
