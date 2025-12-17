package model

// RegisterRequest defines payload for user registration.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest defines payload for user login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
