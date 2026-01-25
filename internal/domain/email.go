package domain

import "context"

// EmailService defines behavior for sending emails.
type EmailService interface {
	SendOTP(ctx context.Context, email, code string) error
	SendNewPassword(ctx context.Context, email, password string) error
}
