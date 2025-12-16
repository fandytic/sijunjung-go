package auth

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/example/sijunjung-go/internal/domain"
	"github.com/example/sijunjung-go/internal/model"
)

// Service coordinates authentication workflows.
type Service struct {
	users  domain.UserRepository
	tokens domain.TokenRepository
	secret string
	logger domain.AppLogger
}

// NewService constructs the authentication service.
func NewService(users domain.UserRepository, tokens domain.TokenRepository, secret string, logger domain.AppLogger) *Service {
	return &Service{users: users, tokens: tokens, secret: secret, logger: logger}
}

// Register creates a new user.
func (s *Service) Register(ctx context.Context, email, password string) (*model.User, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &model.User{Email: email, PasswordHash: string(hashed), CreatedAt: time.Now()}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	s.logger.Info(ctx, "registered user "+user.Email)
	return user, nil
}

// Login verifies credentials and issues a bearer token.
func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", errors.New("invalid credentials")
	}

	tokenString, expires := s.signToken(user.ID.Hex())
	record := model.Token{Token: tokenString, UserID: user.ID.Hex(), ExpiresAt: expires, CreatedAt: time.Now()}
	if err := s.tokens.Save(ctx, record); err != nil {
		return "", err
	}

	s.logger.Info(ctx, "login for user "+user.Email)
	return tokenString, nil
}

// Logout revokes an existing token.
func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("missing token")
	}
	if err := s.tokens.Delete(ctx, token); err != nil {
		return err
	}
	s.logger.Info(ctx, "logout: "+token)
	return nil
}

// ValidateToken parses and validates a bearer token, returning the user ID when valid.
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (string, error) {
	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.secret), nil
	})
	if err != nil || !parsed.Valid {
		return "", errors.New("unable to parse token")
	}

	if claims, ok := parsed.Claims.(jwt.MapClaims); ok {
		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				return "", errors.New("token expired")
			}
		}
		if sub, ok := claims["sub"].(string); ok {
			valid, userID, err := s.tokens.IsValid(ctx, tokenString)
			if err != nil || !valid {
				return "", errors.New("token revoked")
			}
			if userID != sub {
				return "", errors.New("token subject mismatch")
			}
			return sub, nil
		}
	}
	return "", errors.New("invalid token claims")
}

func (s *Service) signToken(userID string) (string, time.Time) {
	expiresAt := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": expiresAt.Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(s.secret))
	return tokenString, expiresAt
}
