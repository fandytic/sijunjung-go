package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds application configuration values.
type Config struct {
	MongoURI            string
	Database            string
	AuthSecret          string
	HTTPPort            string
	AccessTokenExpiry   time.Duration
	RefreshTokenExpiry  time.Duration
	MailjetAPIKey       string
	MailjetSecretKey    string
	MailjetFromName     string
	MailjetFromEmail    string
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleRedirectURL   string
	FacebookAppID       string
	FacebookAppSecret   string
	FonnteToken         string
	LogRetentionDays    int
	LogCleanupInterval  time.Duration
	SuperAdminEmail     string
	SuperAdminPassword  string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() Config {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		panic("AUTH_SECRET environment variable must be set")
	}
	cfg := Config{
		MongoURI:            envOrDefault("MONGO_URI", "mongodb://localhost:27017"),
		Database:            envOrDefault("MONGO_DB", "sijunjunggo"),
		AuthSecret:          secret,
		HTTPPort:            envOrDefault("HTTP_PORT", "8080"),
		AccessTokenExpiry:   parseDuration("ACCESS_TOKEN_EXPIRY", 24*time.Hour),
		RefreshTokenExpiry:  parseDuration("REFRESH_TOKEN_EXPIRY", 168*time.Hour),
		MailjetAPIKey:       os.Getenv("MAILJET_API_KEY"),
		MailjetSecretKey:    os.Getenv("MAILJET_SECRET_KEY"),
		MailjetFromName:     envOrDefault("MAILJET_FROM_NAME", "Sijunjung Go"),
		MailjetFromEmail:    envOrDefault("MAILJET_FROM_EMAIL", "noreply@sijunjung.go"),
		GoogleClientID:      os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:  os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:   os.Getenv("GOOGLE_REDIRECT_URL"),
		FacebookAppID:       os.Getenv("FACEBOOK_APP_ID"),
		FacebookAppSecret:   os.Getenv("FACEBOOK_APP_SECRET"),
		FonnteToken:         os.Getenv("FONNTE_TOKEN"),
		LogRetentionDays:    parseInt("LOG_RETENTION_DAYS", 30),
		LogCleanupInterval:  parseDuration("LOG_CLEANUP_INTERVAL", 24*time.Hour),
		SuperAdminEmail:     os.Getenv("SUPER_ADMIN_EMAIL"),
		SuperAdminPassword:  os.Getenv("SUPER_ADMIN_PASSWORD"),
	}
	return cfg
}

// parseDuration reads a duration string from an environment variable.
// Supports Go duration format (e.g. "24h", "30m", "168h").
func parseDuration(key string, fallback time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return fallback
	}
	return d
}

func parseInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return n
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
