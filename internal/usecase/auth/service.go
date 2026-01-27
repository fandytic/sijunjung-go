package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/example/sijunjung-go/internal/domain"
	"github.com/example/sijunjung-go/internal/model"
)

const (
	otpExpiry      = 5 * time.Minute
	resendCooldown = 1 * time.Minute
)

// FacebookUserInfo represents the response from Facebook's Graph API /me endpoint.
type FacebookUserInfo struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// FacebookErrorResponse represents an error response from Facebook's Graph API.
type FacebookErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    int    `json:"code"`
	} `json:"error"`
}

// GoogleOAuthTokenResponse represents the response from Google's token endpoint.
type GoogleOAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// GoogleUserInfo represents the response from Google's userinfo endpoint.
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

// Service coordinates authentication workflows.
type Service struct {
	users              domain.UserRepository
	tokens             domain.TokenRepository
	otps               domain.OTPRepository
	email              domain.EmailService
	whatsapp           domain.WhatsAppService
	secret             string
	googleClientID     string
	googleClientSecret string
	googleRedirectURL  string
	facebookAppID      string
	facebookAppSecret  string
	logger             domain.AppLogger
}

// NewService constructs the authentication service.
func NewService(users domain.UserRepository, tokens domain.TokenRepository, otps domain.OTPRepository, email domain.EmailService, whatsapp domain.WhatsAppService, secret, googleClientID, googleClientSecret, googleRedirectURL, facebookAppID, facebookAppSecret string, logger domain.AppLogger) *Service {
	return &Service{
		users:              users,
		tokens:             tokens,
		otps:               otps,
		email:              email,
		whatsapp:           whatsapp,
		secret:             secret,
		googleClientID:     googleClientID,
		googleClientSecret: googleClientSecret,
		googleRedirectURL:  googleRedirectURL,
		facebookAppID:      facebookAppID,
		facebookAppSecret:  facebookAppSecret,
		logger:             logger,
	}
}

// GetGoogleAuthURL returns the URL to redirect users to Google OAuth consent page.
func (s *Service) GetGoogleAuthURL(state string) string {
	params := url.Values{}
	params.Set("client_id", s.googleClientID)
	params.Set("redirect_uri", s.googleRedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("access_type", "offline")
	params.Set("state", state)

	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

// GoogleCallback exchanges the authorization code for tokens and user info.
func (s *Service) GoogleCallback(ctx context.Context, code string) (string, bool, error) {
	// Exchange authorization code for tokens
	tokenResp, err := s.exchangeGoogleCode(ctx, code)
	if err != nil {
		return "", false, err
	}

	// Get user info from Google
	userInfo, err := s.getGoogleUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return "", false, err
	}

	if !userInfo.VerifiedEmail {
		return "", false, errors.New("Email Google belum diverifikasi")
	}

	// Check if user exists
	isNewUser := false
	user, err := s.users.FindByEmail(ctx, userInfo.Email)
	if err != nil {
		// User doesn't exist, create new one
		isNewUser = true
		user = &model.User{
			FullName:     userInfo.Name,
			Email:        userInfo.Email,
			AuthProvider: model.AuthProviderGoogle,
			CreatedAt:    time.Now(),
		}
		if err := s.users.Create(ctx, user); err != nil {
			return "", false, err
		}
		s.logger.Info(ctx, "registered new Google user "+user.Email)
	}

	// Generate token
	tokenString, expires, err := s.signToken(user.ID.Hex())
	if err != nil {
		return "", false, err
	}
	record := model.Token{Token: tokenString, UserID: user.ID.Hex(), ExpiresAt: expires, CreatedAt: time.Now()}
	if err := s.tokens.Save(ctx, record); err != nil {
		return "", false, err
	}

	if !isNewUser {
		s.logger.Info(ctx, "Google login for user "+user.Email)
	}
	return tokenString, isNewUser, nil
}

// exchangeGoogleCode exchanges the authorization code for tokens.
func (s *Service) exchangeGoogleCode(ctx context.Context, code string) (*GoogleOAuthTokenResponse, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", s.googleClientID)
	data.Set("client_secret", s.googleClientSecret)
	data.Set("redirect_uri", s.googleRedirectURL)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Gagal menghubungi server Google")
	}
	defer resp.Body.Close()

	var tokenResp GoogleOAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, errors.New("Gagal memproses respons dari Google")
	}

	if tokenResp.Error != "" {
		return nil, errors.New("Kode otorisasi Google tidak valid: " + tokenResp.ErrorDesc)
	}

	return &tokenResp, nil
}

// getGoogleUserInfo fetches user info from Google using the access token.
func (s *Service) getGoogleUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Gagal mengambil data pengguna dari Google")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Gagal mengambil data pengguna dari Google")
	}

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, errors.New("Gagal memproses data pengguna dari Google")
	}

	return &userInfo, nil
}

// FacebookAuth authenticates a user with Facebook access token.
// If the user doesn't exist, it creates a new account.
func (s *Service) FacebookAuth(ctx context.Context, accessToken string) (string, bool, error) {
	// Verify Facebook access token
	userInfo, err := s.verifyFacebookToken(ctx, accessToken)
	if err != nil {
		return "", false, err
	}

	if userInfo.Email == "" {
		return "", false, errors.New("Izin akses email Facebook tidak diberikan")
	}

	// Check if user exists
	isNewUser := false
	user, err := s.users.FindByEmail(ctx, userInfo.Email)
	if err != nil {
		// User doesn't exist, create new one
		isNewUser = true
		user = &model.User{
			FullName:     userInfo.Name,
			Email:        userInfo.Email,
			AuthProvider: model.AuthProviderFacebook,
			CreatedAt:    time.Now(),
		}
		if err := s.users.Create(ctx, user); err != nil {
			return "", false, err
		}
		s.logger.Info(ctx, "registered new Facebook user "+user.Email)
	}

	// Generate token
	tokenString, expires, err := s.signToken(user.ID.Hex())
	if err != nil {
		return "", false, err
	}
	record := model.Token{Token: tokenString, UserID: user.ID.Hex(), ExpiresAt: expires, CreatedAt: time.Now()}
	if err := s.tokens.Save(ctx, record); err != nil {
		return "", false, err
	}

	if !isNewUser {
		s.logger.Info(ctx, "Facebook login for user "+user.Email)
	}
	return tokenString, isNewUser, nil
}

// verifyFacebookToken verifies the Facebook access token and returns user info.
func (s *Service) verifyFacebookToken(ctx context.Context, accessToken string) (*FacebookUserInfo, error) {
	// Call Facebook's Graph API /me endpoint
	url := "https://graph.facebook.com/me?fields=id,name,email&access_token=" + accessToken
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Gagal memverifikasi akun Facebook")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp FacebookErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error.Message != "" {
			return nil, errors.New("Token Facebook tidak valid")
		}
		return nil, errors.New("Token Facebook tidak valid")
	}

	var userInfo FacebookUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, errors.New("Gagal memproses data dari Facebook")
	}

	return &userInfo, nil
}

// Register creates a new user and sends OTP for verification.
func (s *Service) Register(ctx context.Context, fullName, email, password string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &model.User{FullName: fullName, Email: email, PasswordHash: string(hashed), AuthProvider: model.AuthProviderLocal, CreatedAt: time.Now()}
	if err := s.users.Create(ctx, user); err != nil {
		return err
	}

	// Generate and send OTP
	code := s.generateOTPCode()
	otp := &model.OTP{
		UserID:    user.ID.Hex(),
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(otpExpiry),
		Verified:  false,
		CreatedAt: time.Now(),
	}
	if err := s.otps.Save(ctx, otp); err != nil {
		return err
	}

	if err := s.email.SendOTP(ctx, email, code); err != nil {
		s.logger.Error(ctx, "failed to send OTP email: "+err.Error())
		return errors.New("Gagal mengirim email verifikasi")
	}

	s.logger.Info(ctx, "registered user "+user.Email+" and sent OTP")
	return nil
}

// VerifyOTP verifies the OTP code and returns a token if valid.
func (s *Service) VerifyOTP(ctx context.Context, email, code string) (string, error) {
	otp, err := s.otps.FindByEmail(ctx, email)
	if err != nil {
		return "", errors.New("Kode verifikasi tidak ditemukan")
	}

	if otp.Verified {
		return "", errors.New("Email sudah diverifikasi sebelumnya")
	}

	if time.Now().After(otp.ExpiresAt) {
		return "", errors.New("Kode verifikasi sudah kedaluwarsa")
	}

	if otp.Code != code {
		return "", errors.New("Kode verifikasi tidak valid")
	}

	// Mark as verified
	if err := s.otps.MarkVerified(ctx, email); err != nil {
		return "", err
	}

	// Get user and generate token
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	tokenString, expires, err := s.signToken(user.ID.Hex())
	if err != nil {
		return "", err
	}
	record := model.Token{Token: tokenString, UserID: user.ID.Hex(), ExpiresAt: expires, CreatedAt: time.Now()}
	if err := s.tokens.Save(ctx, record); err != nil {
		return "", err
	}

	s.logger.Info(ctx, "verified OTP for user "+email)
	return tokenString, nil
}

// ResendOTP resends the OTP code with 1 minute cooldown.
func (s *Service) ResendOTP(ctx context.Context, email string) error {
	// Check if user exists
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return errors.New("Email tidak terdaftar")
	}

	// Check cooldown
	existingOTP, err := s.otps.FindByEmail(ctx, email)
	if err == nil && existingOTP != nil {
		if existingOTP.Verified {
			return errors.New("Email sudah diverifikasi sebelumnya")
		}
		timeSinceLastOTP := time.Since(existingOTP.CreatedAt)
		if timeSinceLastOTP < resendCooldown {
			remaining := resendCooldown - timeSinceLastOTP
			return fmt.Errorf("Mohon tunggu %d detik sebelum meminta kode baru", int(remaining.Seconds()))
		}
	}

	// Generate new OTP
	code := s.generateOTPCode()
	otp := &model.OTP{
		UserID:    user.ID.Hex(),
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(otpExpiry),
		Verified:  false,
		CreatedAt: time.Now(),
	}
	if err := s.otps.Save(ctx, otp); err != nil {
		return err
	}

	if err := s.email.SendOTP(ctx, email, code); err != nil {
		s.logger.Error(ctx, "failed to send OTP email: "+err.Error())
		return errors.New("Gagal mengirim email verifikasi")
	}

	s.logger.Info(ctx, "resent OTP for user "+email)
	return nil
}

// generateOTPCode generates a 4-digit OTP code.
func (s *Service) generateOTPCode() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%04d", int(b[0])%10*1000+int(b[1])%10*100+int(b[2])%10*10+int(b[3])%10)
}

// ResetPassword generates a new random password and sends it to user's email.
func (s *Service) ResetPassword(ctx context.Context, email string) error {
	// Check if user exists
	_, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return errors.New("Email tidak terdaftar")
	}

	// Generate random password
	newPassword := s.generateRandomPassword(8)

	// Hash the new password
	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update password in database
	if err := s.users.UpdatePassword(ctx, email, string(hashed)); err != nil {
		return err
	}

	// Send new password via email
	if err := s.email.SendNewPassword(ctx, email, newPassword); err != nil {
		s.logger.Error(ctx, "failed to send new password email: "+err.Error())
		return errors.New("Gagal mengirim email password baru")
	}

	s.logger.Info(ctx, "reset password for user "+email)
	return nil
}

// generateRandomPassword generates a random alphanumeric password.
func (s *Service) generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
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

	tokenString, expires, err := s.signToken(user.ID.Hex())
	if err != nil {
		return "", err
	}
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
		return errors.New("Token tidak ditemukan")
	}
	if err := s.tokens.Delete(ctx, token); err != nil {
		return err
	}
	s.logger.Info(ctx, "logout: "+token)
	return nil
}

// DeleteAccount permanently deletes a user account and all associated data.
func (s *Service) DeleteAccount(ctx context.Context, userID string) error {
	// Verify user exists
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return errors.New("Akun tidak ditemukan")
	}

	// Delete all tokens for this user
	if err := s.tokens.DeleteByUserID(ctx, userID); err != nil {
		s.logger.Error(ctx, "failed to delete tokens for user "+userID+": "+err.Error())
	}

	// Delete OTP records for this user
	if err := s.otps.DeleteByUserID(ctx, userID); err != nil {
		s.logger.Error(ctx, "failed to delete OTPs for user "+userID+": "+err.Error())
	}

	// Delete the user
	if err := s.users.Delete(ctx, userID); err != nil {
		return errors.New("Gagal menghapus akun")
	}

	s.logger.Info(ctx, "deleted account for user "+user.Email)
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

// normalizePhone converts phone number to standard format (628xxx).
// Accepts: 08123456789, +628123456789, 628123456789
func normalizePhone(phone string) string {
	// Remove spaces and dashes
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")

	// Remove leading +
	phone = strings.TrimPrefix(phone, "+")

	// Convert 08xx to 628xx
	if strings.HasPrefix(phone, "0") {
		phone = "62" + phone[1:]
	}

	return phone
}

// SendWhatsAppOTP sends an OTP code via WhatsApp.
func (s *Service) SendWhatsAppOTP(ctx context.Context, phone string) error {
	// Normalize phone number
	phone = normalizePhone(phone)

	// Check cooldown
	existingOTP, err := s.otps.FindByPhone(ctx, phone)
	if err == nil && existingOTP != nil {
		if existingOTP.Verified {
			return errors.New("Nomor WhatsApp sudah diverifikasi sebelumnya")
		}
		timeSinceLastOTP := time.Since(existingOTP.CreatedAt)
		if timeSinceLastOTP < resendCooldown {
			remaining := resendCooldown - timeSinceLastOTP
			return fmt.Errorf("Mohon tunggu %d detik sebelum meminta kode baru", int(remaining.Seconds()))
		}
	}

	// Generate new OTP
	code := s.generateOTPCode()
	otp := &model.OTP{
		Phone:     phone,
		Code:      code,
		ExpiresAt: time.Now().Add(otpExpiry),
		Verified:  false,
		CreatedAt: time.Now(),
	}
	if err := s.otps.SaveByPhone(ctx, otp); err != nil {
		return err
	}

	if err := s.whatsapp.SendOTP(ctx, phone, code); err != nil {
		s.logger.Error(ctx, "failed to send WhatsApp OTP: "+err.Error())
		return errors.New("Gagal mengirim kode verifikasi ke WhatsApp")
	}

	s.logger.Info(ctx, "sent WhatsApp OTP to "+phone)
	return nil
}

// VerifyWhatsAppOTP verifies the OTP code sent via WhatsApp.
func (s *Service) VerifyWhatsAppOTP(ctx context.Context, phone, code string) error {
	// Normalize phone number
	phone = normalizePhone(phone)

	otp, err := s.otps.FindByPhone(ctx, phone)
	if err != nil {
		return errors.New("Kode verifikasi tidak ditemukan")
	}

	if otp.Verified {
		return errors.New("Nomor WhatsApp sudah diverifikasi sebelumnya")
	}

	if time.Now().After(otp.ExpiresAt) {
		return errors.New("Kode verifikasi sudah kedaluwarsa")
	}

	if otp.Code != code {
		return errors.New("Kode verifikasi tidak valid")
	}

	// Mark as verified
	if err := s.otps.MarkVerifiedByPhone(ctx, phone); err != nil {
		return err
	}

	s.logger.Info(ctx, "verified WhatsApp OTP for "+phone)
	return nil
}

func (s *Service) signToken(userID string) (string, time.Time, error) {
	expiresAt := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": expiresAt.Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.secret))
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, expiresAt, nil
}
