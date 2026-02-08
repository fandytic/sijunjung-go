package http

import (
	"encoding/json"
	"net/http"

	"github.com/example/sijunjung-go/internal/model"
	"github.com/example/sijunjung-go/internal/usecase/auth"
)

// MerchantHandler exposes HTTP endpoints for merchant operations.
type MerchantHandler struct {
	service *auth.Service
}

// NewMerchantHandler builds a MerchantHandler.
func NewMerchantHandler(service *auth.Service) *MerchantHandler {
	return &MerchantHandler{service: service}
}

// Login godoc
// @Summary Login merchant
// @Description Authenticate merchant with email and password
// @Tags merchant
// @Accept json
// @Produce json
// @Param request body model.LoginRequest true "Login request"
// @Success 200 {object} APIResponse{data=TokenData} "Login successful"
// @Failure 400 {object} APIErrorResponse "Invalid request body"
// @Failure 401 {object} APIErrorResponse "Invalid credentials or unauthorized role"
// @Router /api/merchant/login [post]
func (h *MerchantHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, refreshToken, err := h.service.LoginWithRole(r.Context(), req.Email, req.Password, model.RoleMerchant)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Login merchant berhasil", TokenData{Token: token, RefreshToken: refreshToken})
}

// Dashboard godoc
// @Summary Merchant dashboard
// @Description Get merchant dashboard data
// @Tags merchant
// @Security BearerAuth
// @Produce json
// @Success 200 {object} APIResponse "Dashboard data"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Failure 403 {object} APIErrorResponse "Forbidden - Merchant only"
// @Router /api/merchant/dashboard [get]
func (h *MerchantHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextUserIDKey).(string)
	respondSuccess(w, http.StatusOK, "Dashboard merchant", map[string]string{"user_id": userID})
}
