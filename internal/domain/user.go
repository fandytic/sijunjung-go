package domain

import (
	"context"

	"github.com/example/sijunjung-go/internal/model"
)

// UserRepository defines persistence behavior for users.
type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	FindByID(ctx context.Context, id string) (*model.User, error)
	FindByRole(ctx context.Context, role model.UserRole) ([]*model.User, error)
	Update(ctx context.Context, id string, user *model.User) error
	UpdatePassword(ctx context.Context, email, passwordHash string) error
	Delete(ctx context.Context, id string) error
}
