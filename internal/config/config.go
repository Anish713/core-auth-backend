package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Server configuration
	Port        string `json:"port"`
	Environment string `json:"environment"`

	// Database configuration
	DatabaseURL string `json:"database_url"`

	// JWT configuration
	JWTSecret        string        `json:"jwt_secret"`
	JWTAccessExpiry  time.Duration `json:"jwt_access_expiry"`
	JWTRefreshExpiry time.Duration `json:"jwt_refresh_expiry"`

	// Email configuration (for forgot password)
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	FromEmail    string `json:"from_email"`

	// Rate limiting
	RateLimitEnabled bool `json:"rate_limit_enabled"`
	RateLimitRPS     int  `json:"rate_limit_rps"`

	// Security
	BCryptCost          int           `json:"bcrypt_cost"`
	PasswordResetExpiry time.Duration `json:"password_reset_expiry"`
	MaxLoginAttempts    int           `json:"max_login_attempts"`
	AccountLockDuration time.Duration `json:"account_lock_duration"`
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		// Default values
		Port:                getEnv("PORT", "8080"),
		Environment:         getEnv("ENV", "development"),
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://postgres:password@localhost:5432/auth_service?sslmode=disable"),
		JWTSecret:           getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production"),
		JWTAccessExpiry:     getDurationEnv("JWT_ACCESS_EXPIRY", 15*time.Minute),
		JWTRefreshExpiry:    getDurationEnv("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
		SMTPHost:            getEnv("SMTP_HOST", ""),
		SMTPPort:            getIntEnv("SMTP_PORT", 587),
		SMTPUsername:        getEnv("SMTP_USERNAME", ""),
		SMTPPassword:        getEnv("SMTP_PASSWORD", ""),
		FromEmail:           getEnv("FROM_EMAIL", "noreply@yourapp.com"),
		RateLimitEnabled:    getBoolEnv("RATE_LIMIT_ENABLED", true),
		RateLimitRPS:        getIntEnv("RATE_LIMIT_RPS", 10),
		BCryptCost:          getIntEnv("BCRYPT_COST", 12),
		PasswordResetExpiry: getDurationEnv("PASSWORD_RESET_EXPIRY", 1*time.Hour),
		MaxLoginAttempts:    getIntEnv("MAX_LOGIN_ATTEMPTS", 5),
		AccountLockDuration: getDurationEnv("ACCOUNT_LOCK_DURATION", 15*time.Minute),
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// validate ensures all required configuration is present and valid
func (c *Config) validate() error {
	if c.Port == "" {
		return fmt.Errorf("PORT is required")
	}

	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	if c.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}

	if len(c.JWTSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters long")
	}

	if c.Environment != "development" && c.Environment != "staging" && c.Environment != "production" {
		return fmt.Errorf("ENV must be one of: development, staging, production")
	}

	if c.BCryptCost < 10 || c.BCryptCost > 15 {
		return fmt.Errorf("BCRYPT_COST must be between 10 and 15")
	}

	return nil
}

// IsDevelopment returns true if the environment is development
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction returns true if the environment is production
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// Helper functions for environment variable parsing

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// GetDatabaseConfig parses database URL into components
func (c *Config) GetDatabaseConfig() (map[string]string, error) {
	// Simple parsing of postgres URL
	// postgres://username:password@host:port/database?sslmode=disable
	url := c.DatabaseURL
	if !strings.HasPrefix(url, "postgres://") {
		return nil, fmt.Errorf("invalid database URL format")
	}

	// Remove postgres:// prefix
	url = strings.TrimPrefix(url, "postgres://")

	config := make(map[string]string)

	// Split by @ to separate auth from host
	parts := strings.Split(url, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid database URL format")
	}

	// Parse username:password
	authParts := strings.Split(parts[0], ":")
	if len(authParts) == 2 {
		config["user"] = authParts[0]
		config["password"] = authParts[1]
	}

	// Parse host:port/database?params
	hostPart := parts[1]

	// Split by ? to separate database from params
	dbParts := strings.Split(hostPart, "?")

	// Parse host:port/database
	hostDbParts := strings.Split(dbParts[0], "/")
	if len(hostDbParts) == 2 {
		config["dbname"] = hostDbParts[1]

		// Parse host:port
		hostPortParts := strings.Split(hostDbParts[0], ":")
		config["host"] = hostPortParts[0]
		if len(hostPortParts) == 2 {
			config["port"] = hostPortParts[1]
		}
	}

	// Parse query parameters
	if len(dbParts) == 2 {
		params := strings.Split(dbParts[1], "&")
		for _, param := range params {
			keyValue := strings.Split(param, "=")
			if len(keyValue) == 2 {
				config[keyValue[0]] = keyValue[1]
			}
		}
	}

	return config, nil
}
