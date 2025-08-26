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

	// Redis configuration
	RedisURL      string `json:"redis_url"`
	RedisPassword string `json:"redis_password"`
	RedisDB       int    `json:"redis_db"`
	RedisEnabled  bool   `json:"redis_enabled"`

	// Email verification configuration
	EmailVerificationEnabled bool          `json:"email_verification_enabled"`
	EmailVerificationExpiry  time.Duration `json:"email_verification_expiry"`

	// Email notification configuration
	SendWelcomeEmail         bool `json:"send_welcome_email"`
	SendPasswordChangedEmail bool `json:"send_password_changed_email"`
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
		RedisURL:            getEnv("REDIS_URL", "localhost:6379"),
		RedisPassword:       getEnv("REDIS_PASSWORD", ""),
		RedisDB:             getIntEnv("REDIS_DB", 0),
		RedisEnabled:        getBoolEnv("REDIS_ENABLED", true),

		// Email verification configuration
		EmailVerificationEnabled: getBoolEnv("EMAIL_VERIFICATION_ENABLED", true),
		EmailVerificationExpiry:  getDurationEnv("EMAIL_VERIFICATION_EXPIRY", 24*time.Hour),

		// Email notification configuration
		SendWelcomeEmail:         getBoolEnv("SEND_WELCOME_EMAIL", true),
		SendPasswordChangedEmail: getBoolEnv("SEND_PASSWORD_CHANGED_EMAIL", true),
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

	if c.RedisEnabled && c.RedisURL == "" {
		return fmt.Errorf("REDIS_URL is required when Redis is enabled")
	}

	// Validate email configuration for production
	if c.IsProduction() {
		if c.SMTPHost == "" {
			return fmt.Errorf("SMTP_HOST is required in production environment")
		}
		if c.SMTPPort == 0 {
			return fmt.Errorf("SMTP_PORT is required in production environment")
		}
		if c.SMTPUsername == "" {
			return fmt.Errorf("SMTP_USERNAME is required in production environment")
		}
		if c.SMTPPassword == "" {
			return fmt.Errorf("SMTP_PASSWORD is required in production environment")
		}
		if c.FromEmail == "" {
			return fmt.Errorf("FROM_EMAIL is required in production environment")
		}
		// Basic email format validation
		if !strings.Contains(c.FromEmail, "@") || !strings.Contains(c.FromEmail, ".") {
			return fmt.Errorf("FROM_EMAIL must be a valid email address")
		}
	}

	// Validate SMTP port range
	if c.SMTPPort != 0 && (c.SMTPPort < 1 || c.SMTPPort > 65535) {
		return fmt.Errorf("SMTP_PORT must be between 1 and 65535")
	}

	// Validate password reset expiry
	if c.PasswordResetExpiry < time.Minute {
		return fmt.Errorf("PASSWORD_RESET_EXPIRY must be at least 1 minute")
	}
	if c.PasswordResetExpiry > 24*time.Hour {
		return fmt.Errorf("PASSWORD_RESET_EXPIRY must not exceed 24 hours")
	}

	// Validate email verification expiry
	if c.EmailVerificationExpiry < time.Hour {
		return fmt.Errorf("EMAIL_VERIFICATION_EXPIRY must be at least 1 hour")
	}
	if c.EmailVerificationExpiry > 7*24*time.Hour {
		return fmt.Errorf("EMAIL_VERIFICATION_EXPIRY must not exceed 7 days")
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

// IsEmailEnabled returns true if email configuration is present
func (c *Config) IsEmailEnabled() bool {
	return c.SMTPHost != "" && c.SMTPPort != 0 && c.FromEmail != ""
}

// GetEmailConfig returns email configuration
func (c *Config) GetEmailConfig() map[string]interface{} {
	return map[string]interface{}{
		"smtp_host":     c.SMTPHost,
		"smtp_port":     c.SMTPPort,
		"smtp_username": c.SMTPUsername,
		"from_email":    c.FromEmail,
		"enabled":       c.IsEmailEnabled(),
	}
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
