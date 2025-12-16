package domain

import (
	"context"

	"github.com/example/sijunjung-go/internal/model"
)

// TokenRepository defines persistence behavior for issued tokens.
type TokenRepository interface {
	Save(ctx context.Context, token model.Token) error
	Delete(ctx context.Context, token string) error
	IsValid(ctx context.Context, token string) (bool, string, error)
}
