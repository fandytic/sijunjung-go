package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/example/sijunjung-go/internal/model"
	"github.com/example/sijunjung-go/internal/usecase/auth"
)

// CMSHandler exposes HTTP endpoints for CMS administrative operations.
type CMSHandler struct {
	service *auth.Service
}

// NewCMSHandler builds a CMSHandler.
func NewCMSHandler(service *auth.Service) *CMSHandler {
	return &CMSHandler{service: service}
}

// Login godoc
// @Summary Login CMS
// @Description Authenticate Super Admin or Admin with email and password
// @Tags cms
// @Accept json
// @Produce json
// @Param request body model.LoginRequest true "Login request"
// @Success 200 {object} APIResponse{data=TokenData} "Login successful"
// @Failure 400 {object} APIErrorResponse "Invalid request body"
// @Failure 401 {object} APIErrorResponse "Invalid credentials or unauthorized role"
// @Router /api/cms/login [post]
func (h *CMSHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, refreshToken, err := h.service.LoginWithRole(r.Context(), req.Email, req.Password, model.RoleSuperAdmin, model.RoleAdmin)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Login CMS berhasil", TokenData{Token: token, RefreshToken: refreshToken})
}

// CreateAccount godoc
// @Summary Create account
// @Description Create a new Admin, Merchant, or Mitra account (Super Admin only)
// @Tags cms
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body model.CreateAccountRequest true "Create account request"
// @Success 201 {object} APIResponse "Account created successfully"
// @Failure 400 {object} APIErrorResponse "Invalid request or email already exists"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Failure 403 {object} APIErrorResponse "Forbidden - Super Admin only"
// @Router /api/cms/accounts [post]
func (h *CMSHandler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	var req model.CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	if req.FullName == "" || req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Nama lengkap, email, dan password harus diisi")
		return
	}

	if !req.Role.IsValid() || req.Role == model.RoleSuperAdmin || req.Role == model.RoleUser {
		respondError(w, http.StatusBadRequest, "Role tidak valid. Gunakan: admin, merchant, atau mitra")
		return
	}

	user, err := h.service.CreateAccount(r.Context(), req.FullName, req.Email, req.Password, req.Role)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccess(w, http.StatusCreated, "Akun berhasil dibuat", map[string]any{
		"id":        user.ID.Hex(),
		"full_name": user.FullName,
		"email":     user.Email,
		"role":      user.Role,
	})
}

// ListAccounts godoc
// @Summary List accounts by role
// @Description Get all accounts filtered by role (Super Admin only)
// @Tags cms
// @Security BearerAuth
// @Produce json
// @Param role query string true "Role filter (admin, merchant, or mitra)"
// @Success 200 {object} APIResponse "Accounts list"
// @Failure 400 {object} APIErrorResponse "Invalid role parameter"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Failure 403 {object} APIErrorResponse "Forbidden - Super Admin only"
// @Router /api/cms/accounts [get]
func (h *CMSHandler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	roleParam := r.URL.Query().Get("role")
	if roleParam == "" {
		respondError(w, http.StatusBadRequest, "Parameter role harus diisi (admin, merchant, atau mitra)")
		return
	}

	role := model.UserRole(roleParam)
	if !role.IsValid() || role == model.RoleSuperAdmin || role == model.RoleUser {
		respondError(w, http.StatusBadRequest, "Role tidak valid. Gunakan: admin, merchant, atau mitra")
		return
	}

	users, err := h.service.ListAccountsByRole(r.Context(), role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Gagal mengambil data akun")
		return
	}
	respondSuccess(w, http.StatusOK, "Data akun berhasil diambil", users)
}

// GetAccount godoc
// @Summary Get account detail
// @Description Get a single account by ID (Super Admin only)
// @Tags cms
// @Security BearerAuth
// @Produce json
// @Param id path string true "Account ID"
// @Success 200 {object} APIResponse "Account detail"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Failure 403 {object} APIErrorResponse "Forbidden - Super Admin only"
// @Failure 404 {object} APIErrorResponse "Account not found"
// @Router /api/cms/accounts/{id} [get]
func (h *CMSHandler) GetAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.service.GetAccount(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Akun tidak ditemukan")
		return
	}
	respondSuccess(w, http.StatusOK, "Data akun berhasil diambil", user)
}

// UpdateAccount godoc
// @Summary Update account
// @Description Update an account's full name and/or email (Super Admin only)
// @Tags cms
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Account ID"
// @Param request body model.UpdateAccountRequest true "Update account request"
// @Success 200 {object} APIResponse "Account updated"
// @Failure 400 {object} APIErrorResponse "Invalid request"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Failure 403 {object} APIErrorResponse "Forbidden - Super Admin only"
// @Router /api/cms/accounts/{id} [put]
func (h *CMSHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req model.UpdateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	user, err := h.service.UpdateAccount(r.Context(), id, req.FullName, req.Email)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Akun berhasil diperbarui", user)
}

// DeleteAccount godoc
// @Summary Delete account
// @Description Permanently delete an account (Super Admin only)
// @Tags cms
// @Security BearerAuth
// @Produce json
// @Param id path string true "Account ID"
// @Success 200 {object} APIResponse{data=nil} "Account deleted"
// @Failure 400 {object} APIErrorResponse "Failed to delete"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Failure 403 {object} APIErrorResponse "Forbidden - Super Admin only"
// @Router /api/cms/accounts/{id} [delete]
func (h *CMSHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.service.DeleteAccountByAdmin(r.Context(), id); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusOK, "Akun berhasil dihapus")
}

// ResetAccountPassword godoc
// @Summary Reset account password
// @Description Reset an account's password and return the new password (Super Admin only)
// @Tags cms
// @Security BearerAuth
// @Produce json
// @Param id path string true "Account ID"
// @Success 200 {object} APIResponse "Password reset successfully"
// @Failure 400 {object} APIErrorResponse "Account not found"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Failure 403 {object} APIErrorResponse "Forbidden - Super Admin only"
// @Router /api/cms/accounts/{id}/reset-password [post]
func (h *CMSHandler) ResetAccountPassword(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	newPassword, err := h.service.ResetPasswordByAdmin(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Password berhasil direset", map[string]string{
		"new_password": newPassword,
	})
}
