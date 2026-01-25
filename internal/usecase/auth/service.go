package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// GoogleTokenInfo represents the response from Google's tokeninfo endpoint.
type GoogleTokenInfo struct {
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Error         string `json:"error_description"`
}

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

// Service coordinates authentication workflows.
type Service struct {
	users             domain.UserRepository
	tokens            domain.TokenRepository
	otps              domain.OTPRepository
	email             domain.EmailService
	secret            string
	googleClientID    string
	facebookAppID     string
	facebookAppSecret string
	logger            domain.AppLogger
}

// NewService constructs the authentication service.
func NewService(users domain.UserRepository, tokens domain.TokenRepository, otps domain.OTPRepository, email domain.EmailService, secret, googleClientID, facebookAppID, facebookAppSecret string, logger domain.AppLogger) *Service {
	return &Service{users: users, tokens: tokens, otps: otps, email: email, secret: secret, googleClientID: googleClientID, facebookAppID: facebookAppID, facebookAppSecret: facebookAppSecret, logger: logger}
}

// GoogleAuth authenticates a user with Google ID token.
// If the user doesn't exist, it creates a new account.
func (s *Service) GoogleAuth(ctx context.Context, idToken string) (string, bool, error) {
	// Verify Google ID token
	tokenInfo, err := s.verifyGoogleToken(ctx, idToken)
	if err != nil {
		return "", false, err
	}

	// Check if user exists
	isNewUser := false
	user, err := s.users.FindByEmail(ctx, tokenInfo.Email)
	if err != nil {
		// User doesn't exist, create new one
		isNewUser = true
		user = &model.User{
			FullName:     tokenInfo.Name,
			Email:        tokenInfo.Email,
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

// verifyGoogleToken verifies the Google ID token and returns user info.
func (s *Service) verifyGoogleToken(ctx context.Context, idToken string) (*GoogleTokenInfo, error) {
	// Call Google's tokeninfo endpoint
	url := "https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("failed to verify Google token")
	}
	defer resp.Body.Close()

	var tokenInfo GoogleTokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&tokenInfo); err != nil {
		return nil, errors.New("failed to parse Google token response")
	}

	if tokenInfo.Error != "" {
		return nil, errors.New("invalid Google token: " + tokenInfo.Error)
	}

	// Verify the token is for our app
	if s.googleClientID != "" && tokenInfo.Aud != s.googleClientID {
		return nil, errors.New("Google token not issued for this application")
	}

	if tokenInfo.EmailVerified != "true" {
		return nil, errors.New("Google email not verified")
	}

	return &tokenInfo, nil
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
		return "", false, errors.New("email permission not granted")
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
		return nil, errors.New("failed to verify Facebook token")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp FacebookErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error.Message != "" {
			return nil, errors.New("invalid Facebook token: " + errResp.Error.Message)
		}
		return nil, errors.New("invalid Facebook token")
	}

	var userInfo FacebookUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, errors.New("failed to parse Facebook token response")
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
		return errors.New("failed to send verification email")
	}

	s.logger.Info(ctx, "registered user "+user.Email+" and sent OTP")
	return nil
}

// VerifyOTP verifies the OTP code and returns a token if valid.
func (s *Service) VerifyOTP(ctx context.Context, email, code string) (string, error) {
	otp, err := s.otps.FindByEmail(ctx, email)
	if err != nil {
		return "", errors.New("verification code not found")
	}

	if otp.Verified {
		return "", errors.New("email already verified")
	}

	if time.Now().After(otp.ExpiresAt) {
		return "", errors.New("verification code expired")
	}

	if otp.Code != code {
		return "", errors.New("invalid verification code")
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
		return errors.New("user not found")
	}

	// Check cooldown
	existingOTP, err := s.otps.FindByEmail(ctx, email)
	if err == nil && existingOTP != nil {
		if existingOTP.Verified {
			return errors.New("email already verified")
		}
		timeSinceLastOTP := time.Since(existingOTP.CreatedAt)
		if timeSinceLastOTP < resendCooldown {
			remaining := resendCooldown - timeSinceLastOTP
			return fmt.Errorf("please wait %d seconds before requesting a new code", int(remaining.Seconds()))
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
		return errors.New("failed to send verification email")
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
		return errors.New("user not found")
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
		return errors.New("failed to send new password email")
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
