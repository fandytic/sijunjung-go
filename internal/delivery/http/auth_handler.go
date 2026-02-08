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
	Token        string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// UserData represents the current user data.
// @Description User data
type UserData struct {
	UserID string `json:"user_id" example:"507f1f77bcf86cd799439011"`
	Role   string `json:"role" example:"user"`
}

// GoogleAuthData represents the Google auth response data.
// @Description Google auth data
type GoogleAuthData struct {
	Token        string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	IsNewUser    bool   `json:"is_new_user" example:"true"`
}

// FacebookAuthData represents the Facebook auth response data.
// @Description Facebook auth data
type FacebookAuthData struct {
	Token        string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	IsNewUser    bool   `json:"is_new_user" example:"true"`
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
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.RegisterRequest true "Registration request"
// @Success 201 {object} APIResponse{data=nil} "User created and OTP sent"
// @Failure 400 {object} APIErrorResponse "Invalid request or email already exists"
// @Router /api/user/register [post]
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
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.VerifyOTPRequest true "Verify OTP request"
// @Success 200 {object} APIResponse{data=TokenData} "Verification successful"
// @Failure 400 {object} APIErrorResponse "Invalid or expired code"
// @Router /api/user/verify-otp [post]
func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req model.VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, refreshToken, err := h.service.VerifyOTP(r.Context(), req.Email, req.Code)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Email berhasil diverifikasi", TokenData{Token: token, RefreshToken: refreshToken})
}

// ResendOTP godoc
// @Summary Resend OTP code
// @Description Resend the OTP code to email (1 minute cooldown)
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.ResendOTPRequest true "Resend OTP request"
// @Success 200 {object} APIResponse{data=nil} "OTP resent successfully"
// @Failure 400 {object} APIErrorResponse "User not found or cooldown active"
// @Failure 429 {object} APIErrorResponse "Please wait before requesting new code"
// @Router /api/user/resend-otp [post]
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
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.ResetPasswordRequest true "Reset password request"
// @Success 200 {object} APIResponse{data=nil} "New password sent to email"
// @Failure 400 {object} APIErrorResponse "User not found or invalid request"
// @Router /api/user/reset-password [post]
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

// GoogleAuthRedirect godoc
// @Summary Redirect to Google OAuth
// @Description Redirects user to Google OAuth consent page for login/registration
// @Tags user
// @Param state query string false "State parameter for CSRF protection"
// @Success 302 "Redirect to Google OAuth"
// @Router /api/user/auth/google [get]
func (h *AuthHandler) GoogleAuthRedirect(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "default"
	}
	authURL := h.service.GetGoogleAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GoogleAuthCallback godoc
// @Summary Google OAuth callback
// @Description Handle callback from Google OAuth and return JWT token
// @Tags user
// @Produce json
// @Param code query string true "Authorization code from Google"
// @Param state query string false "State parameter for CSRF protection"
// @Success 200 {object} APIResponse{data=GoogleAuthData} "Authentication successful"
// @Failure 400 {object} APIErrorResponse "Invalid authorization code"
// @Router /api/user/auth/google/callback [get]
func (h *AuthHandler) GoogleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		errorMsg := r.URL.Query().Get("error")
		if errorMsg != "" {
			respondError(w, http.StatusBadRequest, "Otorisasi Google ditolak: "+errorMsg)
			return
		}
		respondError(w, http.StatusBadRequest, "Kode otorisasi tidak ditemukan")
		return
	}

	token, refreshToken, isNewUser, err := h.service.GoogleCallback(r.Context(), code)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	message := "Login dengan Google berhasil"
	if isNewUser {
		message = "Registrasi dengan Google berhasil"
	}
	respondSuccess(w, http.StatusOK, message, GoogleAuthData{Token: token, RefreshToken: refreshToken, IsNewUser: isNewUser})
}

// FacebookAuth godoc
// @Summary Authenticate with Facebook
// @Description Authenticate or register user with Facebook access token
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.FacebookAuthRequest true "Facebook auth request"
// @Success 200 {object} APIResponse{data=FacebookAuthData} "Authentication successful"
// @Failure 400 {object} APIErrorResponse "Invalid Facebook token"
// @Router /api/user/auth/facebook [post]
func (h *AuthHandler) FacebookAuth(w http.ResponseWriter, r *http.Request) {
	var req model.FacebookAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, refreshToken, isNewUser, err := h.service.FacebookAuth(r.Context(), req.AccessToken)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	message := "Login dengan Facebook berhasil"
	if isNewUser {
		message = "Registrasi dengan Facebook berhasil"
	}
	respondSuccess(w, http.StatusOK, message, FacebookAuthData{Token: token, RefreshToken: refreshToken, IsNewUser: isNewUser})
}

// GoogleAuthMobile godoc
// @Summary Authenticate with Google (Mobile)
// @Description Authenticate or register user with Google ID token from mobile client (Flutter)
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.GoogleMobileAuthRequest true "Google mobile auth request"
// @Success 200 {object} APIResponse{data=GoogleAuthData} "Authentication successful"
// @Failure 400 {object} APIErrorResponse "Invalid Google token"
// @Router /api/user/auth/google-mobile [post]
func (h *AuthHandler) GoogleAuthMobile(w http.ResponseWriter, r *http.Request) {
	var req model.GoogleMobileAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	if req.IDToken == "" {
		respondError(w, http.StatusBadRequest, "ID token Google tidak boleh kosong")
		return
	}

	token, refreshToken, isNewUser, err := h.service.GoogleMobileAuth(r.Context(), req.IDToken)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	message := "Login dengan Google berhasil"
	if isNewUser {
		message = "Registrasi dengan Google berhasil"
	}
	respondSuccess(w, http.StatusOK, message, GoogleAuthData{Token: token, RefreshToken: refreshToken, IsNewUser: isNewUser})
}

// Login godoc
// @Summary Login user (legacy)
// @Description Authenticate user with email and password to get bearer token (legacy endpoint, use /api/user/login instead)
// @Tags legacy
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

	token, refreshToken, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Email atau password salah")
		return
	}
	respondSuccess(w, http.StatusOK, "Login berhasil", TokenData{Token: token, RefreshToken: refreshToken})
}

// Logout godoc
// @Summary Logout user
// @Description Revoke the current access token and optionally the refresh token
// @Tags user
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body model.LogoutRequest false "Logout request with optional refresh token"
// @Success 200 {object} APIResponse{data=nil} "Logout successful"
// @Failure 400 {object} APIErrorResponse "Invalid or missing token"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Router /api/user/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	accessToken := extractToken(r)

	var req model.LogoutRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := h.service.Logout(r.Context(), accessToken, req.RefreshToken); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondSuccessNoData(w, http.StatusOK, "Logout berhasil")
}

// RefreshToken godoc
// @Summary Refresh access token
// @Description Use a refresh token to get a new access token and refresh token pair
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.RefreshTokenRequest true "Refresh token request"
// @Success 200 {object} APIResponse{data=TokenData} "Token refreshed successfully"
// @Failure 400 {object} APIErrorResponse "Invalid request body"
// @Failure 401 {object} APIErrorResponse "Invalid or expired refresh token"
// @Router /api/user/refresh-token [post]
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	if req.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "Refresh token harus diisi")
		return
	}

	token, refreshToken, err := h.service.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Token berhasil diperbarui", TokenData{Token: token, RefreshToken: refreshToken})
}

// CurrentUser godoc
// @Summary Get current user
// @Description Get the current authenticated user information including role
// @Tags user
// @Security BearerAuth
// @Produce json
// @Success 200 {object} APIResponse{data=UserData} "Current user info"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Router /api/user/me [get]
func (h *AuthHandler) CurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextUserIDKey).(string)
	role, _ := r.Context().Value(ContextUserRoleKey).(string)
	respondSuccess(w, http.StatusOK, "Data user berhasil diambil", UserData{UserID: userID, Role: role})
}

// DeleteAccount godoc
// @Summary Delete user account
// @Description Permanently delete the current user account and all associated data
// @Tags user
// @Security BearerAuth
// @Produce json
// @Success 200 {object} APIResponse{data=nil} "Account deleted successfully"
// @Failure 400 {object} APIErrorResponse "Failed to delete account"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Router /api/user/account [delete]
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
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.SendWhatsAppOTPRequest true "Send WhatsApp OTP request"
// @Success 200 {object} APIResponse{data=nil} "OTP sent successfully"
// @Failure 400 {object} APIErrorResponse "Invalid request"
// @Failure 429 {object} APIErrorResponse "Please wait before requesting new code"
// @Router /api/user/whatsapp/send-otp [post]
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
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.VerifyWhatsAppOTPRequest true "Verify WhatsApp OTP request"
// @Success 200 {object} APIResponse{data=nil} "Verification successful"
// @Failure 400 {object} APIErrorResponse "Invalid or expired code"
// @Router /api/user/whatsapp/verify-otp [post]
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

// UserLogin godoc
// @Summary Login user
// @Description Authenticate user with email and password (validates role=user)
// @Tags user
// @Accept json
// @Produce json
// @Param request body model.LoginRequest true "Login request"
// @Success 200 {object} APIResponse{data=TokenData} "Login successful"
// @Failure 400 {object} APIErrorResponse "Invalid request body"
// @Failure 401 {object} APIErrorResponse "Invalid credentials or unauthorized role"
// @Router /api/user/login [post]
func (h *AuthHandler) UserLogin(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Format data tidak valid")
		return
	}

	token, refreshToken, err := h.service.LoginWithRole(r.Context(), req.Email, req.Password, model.RoleUser)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respondSuccess(w, http.StatusOK, "Login berhasil", TokenData{Token: token, RefreshToken: refreshToken})
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
