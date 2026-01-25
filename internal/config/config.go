package config

import (
	"os"
)

// Config holds application configuration values.
type Config struct {
	MongoURI          string
	Database          string
	AuthSecret        string
	HTTPPort          string
	SMTPHost          string
	SMTPPort          string
	SMTPUser          string
	SMTPPass          string
	SMTPFrom          string
	GoogleClientID    string
	FacebookAppID     string
	FacebookAppSecret string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() Config {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		panic("AUTH_SECRET environment variable must be set")
	}
	cfg := Config{
		MongoURI:          envOrDefault("MONGO_URI", "mongodb://localhost:27017"),
		Database:          envOrDefault("MONGO_DB", "sijunjunggo"),
		AuthSecret:        secret,
		HTTPPort:          envOrDefault("HTTP_PORT", "8080"),
		SMTPHost:          envOrDefault("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:          envOrDefault("SMTP_PORT", "587"),
		SMTPUser:          os.Getenv("SMTP_USER"),
		SMTPPass:          os.Getenv("SMTP_PASS"),
		SMTPFrom:          envOrDefault("SMTP_FROM", "noreply@sijunjung.go"),
		GoogleClientID:    os.Getenv("GOOGLE_CLIENT_ID"),
		FacebookAppID:     os.Getenv("FACEBOOK_APP_ID"),
		FacebookAppSecret: os.Getenv("FACEBOOK_APP_SECRET"),
	}
	return cfg
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
