package http

import (
	"encoding/json"
	"net/http"

	"github.com/example/sijunjung-go/internal/model"
	"github.com/example/sijunjung-go/internal/usecase/auth"
)

// MitraHandler exposes HTTP endpoints for mitra operations.
type MitraHandler struct {
	service *auth.Service
}

// NewMitraHandler builds a MitraHandler.
func NewMitraHandler(service *auth.Service) *MitraHandler {
	return &MitraHandler{service: service}
}

// Login godoc
// @Summary Login mitra
// @Description Authenticate mitra with email and password
// @Tags mitra
// @Accept json
// @Produce json
// @Param request body model.LoginRequest true "Login request"
// @Success 200 {object} APIResponse{data=TokenData} "Login successful"
// @Failure 400 {object} APIErrorResponse "Invalid request body"
// @Failure 401 {object} APIErrorResponse "Invalid credentials or unauthorized role"
// @Router /api/mitra/login [post]
func (h *MitraHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, refreshToken, err := h.service.LoginWithRole(r.Context(), req.Email, req.Password, model.RoleMitra)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Login mitra berhasil", TokenData{Token: token, RefreshToken: refreshToken})
}

// Dashboard godoc
// @Summary Mitra dashboard
// @Description Get mitra dashboard data
// @Tags mitra
// @Security BearerAuth
// @Produce json
// @Success 200 {object} APIResponse "Dashboard data"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Failure 403 {object} APIErrorResponse "Forbidden - Mitra only"
// @Router /api/mitra/dashboard [get]
func (h *MitraHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextUserIDKey).(string)
	respondSuccess(w, http.StatusOK, "Dashboard mitra", map[string]string{"user_id": userID})
}
