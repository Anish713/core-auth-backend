package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// PasswordValidator handles password validation logic
type PasswordValidator struct {
	minLength      int
	maxLength      int
	requireUpper   bool
	requireLower   bool
	requireNumber  bool
	requireSpecial bool
}

// NewPasswordValidator creates a new password validator with default rules
func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{
		minLength:      8,
		maxLength:      128,
		requireUpper:   true,
		requireLower:   true,
		requireNumber:  true,
		requireSpecial: true,
	}
}

// ValidationError represents a password validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (ve ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", ve.Field, ve.Message)
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string, cost int) (string, error) {
	// Validate cost parameter
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", fmt.Errorf("invalid bcrypt cost: must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hash), nil
}

// VerifyPassword verifies a password against its hash
func VerifyPassword(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return fmt.Errorf("invalid password")
		}
		return fmt.Errorf("failed to verify password: %w", err)
	}

	return nil
}

// ValidatePassword validates a password against security requirements
func (pv *PasswordValidator) ValidatePassword(password string) []ValidationError {
	var errors []ValidationError

	// Check length
	if len(password) < pv.minLength {
		errors = append(errors, ValidationError{
			Field:   "password",
			Message: fmt.Sprintf("password must be at least %d characters long", pv.minLength),
		})
	}

	if len(password) > pv.maxLength {
		errors = append(errors, ValidationError{
			Field:   "password",
			Message: fmt.Sprintf("password must not exceed %d characters", pv.maxLength),
		})
	}

	// Check character requirements
	if pv.requireUpper && !containsUpper(password) {
		errors = append(errors, ValidationError{
			Field:   "password",
			Message: "password must contain at least one uppercase letter",
		})
	}

	if pv.requireLower && !containsLower(password) {
		errors = append(errors, ValidationError{
			Field:   "password",
			Message: "password must contain at least one lowercase letter",
		})
	}

	if pv.requireNumber && !containsNumber(password) {
		errors = append(errors, ValidationError{
			Field:   "password",
			Message: "password must contain at least one number",
		})
	}

	if pv.requireSpecial && !containsSpecial(password) {
		errors = append(errors, ValidationError{
			Field:   "password",
			Message: "password must contain at least one special character",
		})
	}

	// Check for common weak patterns
	if isCommonPassword(password) {
		errors = append(errors, ValidationError{
			Field:   "password",
			Message: "password is too common, please choose a more secure password",
		})
	}

	return errors
}

// ValidateEmail validates an email address format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}

	if len(email) > 255 {
		return fmt.Errorf("email must not exceed 255 characters")
	}

	// Basic email regex pattern
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// GenerateRandomToken generates a cryptographically secure random token
func GenerateRandomToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// GeneratePasswordResetToken generates a secure token for password reset
func GeneratePasswordResetToken() (string, error) {
	return GenerateRandomToken(32) // 64 character hex string
}

// Helper functions for password validation

func containsUpper(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func containsLower(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func containsNumber(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	for _, r := range s {
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			return true
		}
	}
	return false
}

// isCommonPassword checks if the password is in a list of common weak passwords
func isCommonPassword(password string) bool {
	// Convert to lowercase for comparison
	lower := strings.ToLower(password)

	// List of common weak passwords
	commonPasswords := []string{
		"password", "123456", "12345678", "qwerty", "abc123",
		"password123", "admin", "letmein", "welcome", "monkey",
		"dragon", "pass", "master", "hello", "superman",
		"123456789", "1234567890", "123123", "qwertyuiop",
	}

	for _, common := range commonPasswords {
		if lower == common {
			return true
		}
		// Also check if password contains common patterns
		if strings.Contains(lower, common) && len(password) < 12 {
			return true
		}
	}

	return false
}

// SanitizeInput removes potentially harmful characters from user input
func SanitizeInput(input string) string {
	// Remove leading and trailing whitespace
	input = strings.TrimSpace(input)

	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	return input
}

// ValidateName validates user names (first name, last name)
func ValidateName(name, fieldName string) error {
	name = SanitizeInput(name)

	if name == "" {
		return fmt.Errorf("%s is required", fieldName)
	}

	if len(name) < 1 {
		return fmt.Errorf("%s must be at least 1 character long", fieldName)
	}

	if len(name) > 100 {
		return fmt.Errorf("%s must not exceed 100 characters", fieldName)
	}

	// Check for valid characters (letters, spaces, hyphens, apostrophes)
	nameRegex := regexp.MustCompile(`^[a-zA-Z\s\-']+$`)
	if !nameRegex.MatchString(name) {
		return fmt.Errorf("%s contains invalid characters", fieldName)
	}

	return nil
}
