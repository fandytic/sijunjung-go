package config

import (
	"os"
)

// Config holds application configuration values.
type Config struct {
	MongoURI           string
	Database           string
	AuthSecret         string
	HTTPPort           string
	MailjetAPIKey      string
	MailjetSecretKey   string
	MailjetFromName    string
	MailjetFromEmail   string
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	FacebookAppID      string
	FacebookAppSecret  string
	FonnteToken        string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() Config {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		panic("AUTH_SECRET environment variable must be set")
	}
	cfg := Config{
		MongoURI:           envOrDefault("MONGO_URI", "mongodb://localhost:27017"),
		Database:           envOrDefault("MONGO_DB", "sijunjunggo"),
		AuthSecret:         secret,
		HTTPPort:           envOrDefault("HTTP_PORT", "8080"),
		MailjetAPIKey:      os.Getenv("MAILJET_API_KEY"),
		MailjetSecretKey:   os.Getenv("MAILJET_SECRET_KEY"),
		MailjetFromName:    envOrDefault("MAILJET_FROM_NAME", "Sijunjung Go"),
		MailjetFromEmail:   envOrDefault("MAILJET_FROM_EMAIL", "noreply@sijunjung.go"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		FacebookAppID:      os.Getenv("FACEBOOK_APP_ID"),
		FacebookAppSecret:  os.Getenv("FACEBOOK_APP_SECRET"),
		FonnteToken:        os.Getenv("FONNTE_TOKEN"),
	}
	return cfg
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
