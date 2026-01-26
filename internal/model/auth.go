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
