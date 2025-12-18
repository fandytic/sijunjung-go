package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/example/sijunjung-go/internal/model"
	"github.com/example/sijunjung-go/internal/usecase/auth"
)

// AuthHandler exposes HTTP endpoints for authentication flows.
type AuthHandler struct {
	service *auth.Service
}

// NewAuthHandler builds an AuthHandler.
func NewAuthHandler(service *auth.Service) *AuthHandler {
	return &AuthHandler{service: service}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.service.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondSuccess(w, http.StatusCreated, user, "")
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	token, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	respondSuccess(w, http.StatusOK, map[string]string{"token": token}, "")
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if err := h.service.Logout(r.Context(), token); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondSuccess(w, http.StatusOK, map[string]any{}, "logout successful")
}

func (h *AuthHandler) CurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextUserIDKey)
	respondSuccess(w, http.StatusOK, map[string]any{"user_id": userID}, "")
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	if token := r.Header.Get("X-Access-Token"); token != "" {
		return token
	}
	return ""
}
