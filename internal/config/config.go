package config

import (
	"os"
)

// Config holds application configuration values.
type Config struct {
	MongoURI   string
	Database   string
	AuthSecret string
	HTTPPort   string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() Config {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		panic("AUTH_SECRET environment variable must be set")
	}
	cfg := Config{
		MongoURI:   envOrDefault("MONGO_URI", "mongodb://localhost:27017"),
		Database:   envOrDefault("MONGO_DB", "sijunjunggo"),
		AuthSecret: secret,
		HTTPPort:   envOrDefault("HTTP_PORT", "8080"),
	}
	return cfg
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
