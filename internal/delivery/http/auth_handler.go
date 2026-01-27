package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/example/sijunjung-go/internal/model"
	"github.com/example/sijunjung-go/internal/usecase/auth"
)

// TokenData represents the token response data.
// @Description Token data
type TokenData struct {
	Token string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// UserData represents the current user data.
// @Description User data
type UserData struct {
	UserID string `json:"user_id" example:"507f1f77bcf86cd799439011"`
}

// GoogleAuthData represents the Google auth response data.
// @Description Google auth data
type GoogleAuthData struct {
	Token     string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	IsNewUser bool   `json:"is_new_user" example:"true"`
}

// FacebookAuthData represents the Facebook auth response data.
// @Description Facebook auth data
type FacebookAuthData struct {
	Token     string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	IsNewUser bool   `json:"is_new_user" example:"true"`
}

// AuthHandler exposes HTTP endpoints for authentication flows.
type AuthHandler struct {
	service *auth.Service
}

// NewAuthHandler builds an AuthHandler.
func NewAuthHandler(service *auth.Service) *AuthHandler {
	return &AuthHandler{service: service}
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with full name, email, and password. Sends OTP to email for verification.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body model.RegisterRequest true "Registration request"
// @Success 201 {object} APIResponse{data=nil} "User created and OTP sent"
// @Failure 400 {object} APIErrorResponse "Invalid request or email already exists"
// @Router /api/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	if err := h.service.Register(r.Context(), req.FullName, req.Email, req.Password); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusCreated, "Kode verifikasi telah dikirim ke "+req.Email)
}

// VerifyOTP godoc
// @Summary Verify OTP code
// @Description Verify the OTP code sent to email and get bearer token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body model.VerifyOTPRequest true "Verify OTP request"
// @Success 200 {object} APIResponse{data=TokenData} "Verification successful"
// @Failure 400 {object} APIErrorResponse "Invalid or expired code"
// @Router /api/verify-otp [post]
func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req model.VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, err := h.service.VerifyOTP(r.Context(), req.Email, req.Code)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Email berhasil diverifikasi", TokenData{Token: token})
}

// ResendOTP godoc
// @Summary Resend OTP code
// @Description Resend the OTP code to email (1 minute cooldown)
// @Tags auth
// @Accept json
// @Produce json
// @Param request body model.ResendOTPRequest true "Resend OTP request"
// @Success 200 {object} APIResponse{data=nil} "OTP resent successfully"
// @Failure 400 {object} APIErrorResponse "User not found or cooldown active"
// @Failure 429 {object} APIErrorResponse "Please wait before requesting new code"
// @Router /api/resend-otp [post]
func (h *AuthHandler) ResendOTP(w http.ResponseWriter, r *http.Request) {
	var req model.ResendOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	if err := h.service.ResendOTP(r.Context(), req.Email); err != nil {
		if strings.Contains(err.Error(), "Mohon tunggu") {
			respondError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusOK, "Kode verifikasi telah dikirim ke "+req.Email)
}

// ResetPassword godoc
// @Summary Reset password
// @Description Reset password by sending a new random password to user's email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body model.ResetPasswordRequest true "Reset password request"
// @Success 200 {object} APIResponse{data=nil} "New password sent to email"
// @Failure 400 {object} APIErrorResponse "User not found or invalid request"
// @Router /api/reset-password [post]
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req model.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	if err := h.service.ResetPassword(r.Context(), req.Email); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusOK, "Password baru telah dikirim ke "+req.Email)
}

// GoogleAuth godoc
// @Summary Authenticate with Google
// @Description Authenticate or register user with Google ID token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body model.GoogleAuthRequest true "Google auth request"
// @Success 200 {object} APIResponse{data=GoogleAuthData} "Authentication successful"
// @Failure 400 {object} APIErrorResponse "Invalid Google token"
// @Router /api/auth/google [post]
func (h *AuthHandler) GoogleAuth(w http.ResponseWriter, r *http.Request) {
	var req model.GoogleAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, isNewUser, err := h.service.GoogleAuth(r.Context(), req.IDToken)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	message := "Login dengan Google berhasil"
	if isNewUser {
		message = "Registrasi dengan Google berhasil"
	}
	respondSuccess(w, http.StatusOK, message, GoogleAuthData{Token: token, IsNewUser: isNewUser})
}

// FacebookAuth godoc
// @Summary Authenticate with Facebook
// @Description Authenticate or register user with Facebook access token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body model.FacebookAuthRequest true "Facebook auth request"
// @Success 200 {object} APIResponse{data=FacebookAuthData} "Authentication successful"
// @Failure 400 {object} APIErrorResponse "Invalid Facebook token"
// @Router /api/auth/facebook [post]
func (h *AuthHandler) FacebookAuth(w http.ResponseWriter, r *http.Request) {
	var req model.FacebookAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, isNewUser, err := h.service.FacebookAuth(r.Context(), req.AccessToken)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	message := "Login dengan Facebook berhasil"
	if isNewUser {
		message = "Registrasi dengan Facebook berhasil"
	}
	respondSuccess(w, http.StatusOK, message, FacebookAuthData{Token: token, IsNewUser: isNewUser})
}

// Login godoc
// @Summary Login user
// @Description Authenticate user with email and password to get bearer token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body model.LoginRequest true "Login request"
// @Success 200 {object} APIResponse{data=TokenData} "Login successful"
// @Failure 400 {object} APIErrorResponse "Invalid request body"
// @Failure 401 {object} APIErrorResponse "Invalid credentials"
// @Router /api/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Email atau password salah")
		return
	}
	respondSuccess(w, http.StatusOK, "Login berhasil", TokenData{Token: token})
}

// Logout godoc
// @Summary Logout user
// @Description Revoke the current bearer token
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} APIResponse{data=nil} "Logout successful"
// @Failure 400 {object} APIErrorResponse "Invalid or missing token"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Router /api/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if err := h.service.Logout(r.Context(), token); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusOK, "Logout berhasil")
}

// CurrentUser godoc
// @Summary Get current user
// @Description Get the current authenticated user information
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} APIResponse{data=UserData} "Current user info"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Router /api/me [get]
func (h *AuthHandler) CurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextUserIDKey)
	respondSuccess(w, http.StatusOK, "Data user berhasil diambil", UserData{UserID: userID.(string)})
}

// DeleteAccount godoc
// @Summary Delete user account
// @Description Permanently delete the current user account and all associated data
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} APIResponse{data=nil} "Account deleted successfully"
// @Failure 400 {object} APIErrorResponse "Failed to delete account"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Router /api/account [delete]
func (h *AuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextUserIDKey).(string)
	if err := h.service.DeleteAccount(r.Context(), userID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusOK, "Akun berhasil dihapus")
}

// SendWhatsAppOTP godoc
// @Summary Send OTP via WhatsApp
// @Description Send an OTP code to the specified WhatsApp number (1 minute cooldown)
// @Tags whatsapp
// @Accept json
// @Produce json
// @Param request body model.SendWhatsAppOTPRequest true "Send WhatsApp OTP request"
// @Success 200 {object} APIResponse{data=nil} "OTP sent successfully"
// @Failure 400 {object} APIErrorResponse "Invalid request"
// @Failure 429 {object} APIErrorResponse "Please wait before requesting new code"
// @Router /api/whatsapp/send-otp [post]
func (h *AuthHandler) SendWhatsAppOTP(w http.ResponseWriter, r *http.Request) {
	var req model.SendWhatsAppOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	if req.Phone == "" {
		respondError(w, http.StatusBadRequest, "Nomor WhatsApp harus diisi")
		return
	}

	if err := h.service.SendWhatsAppOTP(r.Context(), req.Phone); err != nil {
		if strings.Contains(err.Error(), "Mohon tunggu") {
			respondError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusOK, "Kode verifikasi telah dikirim ke WhatsApp "+req.Phone)
}

// VerifyWhatsAppOTP godoc
// @Summary Verify WhatsApp OTP code
// @Description Verify the OTP code sent to WhatsApp
// @Tags whatsapp
// @Accept json
// @Produce json
// @Param request body model.VerifyWhatsAppOTPRequest true "Verify WhatsApp OTP request"
// @Success 200 {object} APIResponse{data=nil} "Verification successful"
// @Failure 400 {object} APIErrorResponse "Invalid or expired code"
// @Router /api/whatsapp/verify-otp [post]
func (h *AuthHandler) VerifyWhatsAppOTP(w http.ResponseWriter, r *http.Request) {
	var req model.VerifyWhatsAppOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	if req.Phone == "" || req.Code == "" {
		respondError(w, http.StatusBadRequest, "Nomor WhatsApp dan kode OTP harus diisi")
		return
	}

	if err := h.service.VerifyWhatsAppOTP(r.Context(), req.Phone, req.Code); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusOK, "Nomor WhatsApp berhasil diverifikasi")
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
