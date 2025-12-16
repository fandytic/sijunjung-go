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

// Register handles user registration.
// @Summary      Register a new user
// @Description  Create a user account with an email and password.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      model.RegisterRequest  true  "Registration payload"
// @Success      201   {object}  model.User
// @Failure      400   {string}  string
// @Router       /register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.service.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}

// Login verifies credentials and returns a bearer token.
// @Summary      Login and receive bearer token
// @Description  Authenticate with email and password to obtain a bearer token for subsequent requests.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      model.LoginRequest  true  "Login payload"
// @Success      200   {object}  map[string]string
// @Failure      400   {string}  string
// @Failure      401   {string}  string
// @Router       /login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Logout revokes the bearer token on the request.
// @Summary      Logout and revoke bearer token
// @Description  Invalidate the provided bearer token.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      204   {string}  string
// @Failure      400   {string}  string
// @Router       /logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if err := h.service.Logout(r.Context(), token); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CurrentUser returns the authenticated user id for demonstration.
// @Summary      Get current user id
// @Description  Returns the identifier of the authenticated user from the bearer token.
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]any
// @Router       /me [get]
func (h *AuthHandler) CurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextUserIDKey)
	_ = json.NewEncoder(w).Encode(map[string]any{"user_id": userID})
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	if token := r.Header.Get("X-Access-Token"); token != "" {
		return token
	}
	return ""
}
