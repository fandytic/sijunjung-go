package model

// RegisterRequest defines payload for user registration.
// @Description Request body for user registration
type RegisterRequest struct {
	FullName string `json:"full_name" example:"Sijunjung Go"`
	Email    string `json:"email" example:"sijunjunggo@gmail.com"`
	Password string `json:"password" example:"password123"`
}

// LoginRequest defines payload for user login.
// @Description Request body for user login
type LoginRequest struct {
	Email    string `json:"email" example:"sijunjunggo@gmail.com"`
	Password string `json:"password" example:"password123"`
}

// ResetPasswordRequest defines payload for password reset.
// @Description Request body for password reset
type ResetPasswordRequest struct {
	Email string `json:"email" example:"sijunjunggo@gmail.com"`
}

// FacebookAuthRequest defines payload for Facebook OAuth authentication.
// @Description Request body for Facebook authentication
type FacebookAuthRequest struct {
	AccessToken string `json:"access_token" example:"EAABsbCS1..."`
}

// GoogleMobileAuthRequest defines payload for Google OAuth via mobile client.
// @Description Request body for Google authentication from mobile apps (Flutter)
type GoogleMobileAuthRequest struct {
	IDToken string `json:"id_token" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ..."`
}

// RefreshTokenRequest defines payload for refreshing an access token.
// @Description Request body for refreshing access token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}
