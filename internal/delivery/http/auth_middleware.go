package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/example/sijunjung-go/internal/usecase/auth"
)

// AuthMiddleware validates bearer tokens on incoming requests.
type AuthMiddleware struct {
	service *auth.Service
}

// NewAuthMiddleware builds an AuthMiddleware instance.
func NewAuthMiddleware(service *auth.Service) *AuthMiddleware {
	return &AuthMiddleware{service: service}
}

// Handler wraps next handler with bearer validation.
func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondError(w, http.StatusUnauthorized, "Silakan login terlebih dahulu")
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			respondError(w, http.StatusUnauthorized, "Format token tidak valid")
			return
		}
		tokenString := parts[1]

		userID, err := m.service.ValidateToken(ctx, tokenString)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "Sesi telah berakhir, silakan login kembali")
			return
		}

		ctx = context.WithValue(ctx, ContextUserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
