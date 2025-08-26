package errors

import (
	"fmt"
	"net/http"
)

// ErrorCode represents different types of application errors
type ErrorCode string

const (
	// Authentication errors
	ErrInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrAccountLocked      ErrorCode = "ACCOUNT_LOCKED"
	ErrAccountInactive    ErrorCode = "ACCOUNT_INACTIVE"
	ErrTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	ErrTokenInvalid       ErrorCode = "TOKEN_INVALID"
	ErrUnauthorized       ErrorCode = "UNAUTHORIZED"

	// Validation errors
	ErrValidation   ErrorCode = "VALIDATION_ERROR"
	ErrEmailExists  ErrorCode = "EMAIL_EXISTS"
	ErrUserNotFound ErrorCode = "USER_NOT_FOUND"
	ErrInvalidEmail ErrorCode = "INVALID_EMAIL"
	ErrWeakPassword ErrorCode = "WEAK_PASSWORD"

	// System errors
	ErrInternal      ErrorCode = "INTERNAL_ERROR"
	ErrDatabaseError ErrorCode = "DATABASE_ERROR"
	ErrServiceError  ErrorCode = "SERVICE_ERROR"

	// Rate limiting
	ErrRateLimit ErrorCode = "RATE_LIMIT_EXCEEDED"

	// Password reset
	ErrResetTokenExpired ErrorCode = "RESET_TOKEN_EXPIRED"
	ErrResetTokenInvalid ErrorCode = "RESET_TOKEN_INVALID"
)

// AppError represents a structured application error
type AppError struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	Details    string    `json:"details,omitempty"`
	StatusCode int       `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s - %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ValidationErrorDetail represents detailed validation error information
type ValidationErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError represents validation errors with field-specific details
type ValidationError struct {
	*AppError
	Errors []ValidationErrorDetail `json:"errors"`
}

// NewAppError creates a new application error
func NewAppError(code ErrorCode, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

// NewAppErrorWithDetails creates a new application error with details
func NewAppErrorWithDetails(code ErrorCode, message, details string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Details:    details,
		StatusCode: statusCode,
	}
}

// NewValidationError creates a new validation error
func NewValidationError(message string, errors []ValidationErrorDetail) *ValidationError {
	return &ValidationError{
		AppError: &AppError{
			Code:       ErrValidation,
			Message:    message,
			StatusCode: http.StatusBadRequest,
		},
		Errors: errors,
	}
}

// Predefined error instances for common scenarios

// Authentication errors
func ErrInvalidCredentialsError() *AppError {
	return NewAppError(ErrInvalidCredentials, "Invalid email or password", http.StatusUnauthorized)
}

func ErrAccountLockedError(details string) *AppError {
	return NewAppErrorWithDetails(ErrAccountLocked, "Account is locked due to too many failed login attempts", details, http.StatusUnauthorized)
}

func ErrAccountInactiveError() *AppError {
	return NewAppError(ErrAccountInactive, "Account is inactive", http.StatusForbidden)
}

func ErrTokenExpiredError() *AppError {
	return NewAppError(ErrTokenExpired, "Token has expired", http.StatusUnauthorized)
}

func ErrTokenInvalidError() *AppError {
	return NewAppError(ErrTokenInvalid, "Invalid token", http.StatusUnauthorized)
}

func ErrUnauthorizedError() *AppError {
	return NewAppError(ErrUnauthorized, "Unauthorized access", http.StatusUnauthorized)
}

// User errors
func ErrUserNotFoundError() *AppError {
	return NewAppError(ErrUserNotFound, "User not found", http.StatusNotFound)
}

func ErrEmailExistsError() *AppError {
	return NewAppError(ErrEmailExists, "Email address is already registered", http.StatusConflict)
}

func ErrInvalidEmailError() *AppError {
	return NewAppError(ErrInvalidEmail, "Invalid email format", http.StatusBadRequest)
}

// System errors
func NewErrInternalError(details string) *AppError {
	return NewAppErrorWithDetails(ErrInternal, "Internal server error", details, http.StatusInternalServerError)
}

func NewErrDatabaseError(details string) *AppError {
	return NewAppErrorWithDetails(ErrDatabaseError, "Database operation failed", details, http.StatusInternalServerError)
}

func NewErrServiceError(details string) *AppError {
	return NewAppErrorWithDetails(ErrServiceError, "Service operation failed", details, http.StatusInternalServerError)
}

// Rate limiting
func NewErrRateLimitError(details string) *AppError {
	return NewAppErrorWithDetails(ErrRateLimit, "Rate limit exceeded", details, http.StatusTooManyRequests)
}

// Password reset errors
func ErrResetTokenExpiredError() *AppError {
	return NewAppError(ErrResetTokenExpired, "Password reset token has expired", http.StatusBadRequest)
}

func ErrResetTokenInvalidError() *AppError {
	return NewAppError(ErrResetTokenInvalid, "Invalid password reset token", http.StatusBadRequest)
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// GetAppError safely converts an error to AppError
func GetAppError(err error) *AppError {
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}
	// Return a generic internal error for unknown errors
	return NewErrInternalError(err.Error())
}
