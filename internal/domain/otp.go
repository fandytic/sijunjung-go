package domain

import (
	"context"

	"github.com/example/sijunjung-go/internal/model"
)

// OTPRepository defines persistence behavior for OTP codes.
type OTPRepository interface {
	Save(ctx context.Context, otp *model.OTP) error
	FindByEmail(ctx context.Context, email string) (*model.OTP, error)
	MarkVerified(ctx context.Context, email string) error
	Delete(ctx context.Context, email string) error
	DeleteByUserID(ctx context.Context, userID string) error
}
