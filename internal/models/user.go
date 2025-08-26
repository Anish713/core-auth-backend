package models

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID                  int64      `json:"id" db:"id"`
	Email               string     `json:"email" db:"email"`
	PasswordHash        string     `json:"-" db:"password_hash"` // Never include in JSON
	FirstName           string     `json:"first_name" db:"first_name"`
	LastName            string     `json:"last_name" db:"last_name"`
	IsVerified          bool       `json:"is_verified" db:"is_verified"`
	IsActive            bool       `json:"is_active" db:"is_active"`
	FailedLoginAttempts int        `json:"-" db:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"-" db:"locked_until"`
	LastLogin           *time.Time `json:"last_login" db:"last_login"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
}

// UserProfile represents the public profile of a user
type UserProfile struct {
	ID         int64     `json:"id"`
	Email      string    `json:"email"`
	FirstName  string    `json:"first_name"`
	LastName   string    `json:"last_name"`
	IsVerified bool      `json:"is_verified"`
	CreatedAt  time.Time `json:"created_at"`
}

// PasswordReset represents a password reset request
type PasswordReset struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Used      bool      `json:"used" db:"used"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// LoginAttempt represents a login attempt record
type LoginAttempt struct {
	ID          int64     `json:"id" db:"id"`
	Email       string    `json:"email" db:"email"`
	IPAddress   string    `json:"ip_address" db:"ip_address"`
	UserAgent   string    `json:"user_agent" db:"user_agent"`
	Success     bool      `json:"success" db:"success"`
	AttemptedAt time.Time `json:"attempted_at" db:"attempted_at"`
}

// EmailVerification represents an email verification request
type EmailVerification struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Used      bool      `json:"used" db:"used"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// SignUpRequest represents a sign up request
type SignUpRequest struct {
	Email     string `json:"email" validate:"required,email,max=255"`
	Password  string `json:"password" validate:"required,min=8,max=128"`
	FirstName string `json:"first_name" validate:"required,min=1,max=100"`
	LastName  string `json:"last_name" validate:"required,min=1,max=100"`
}

// SignInRequest represents a sign in request
type SignInRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// ForgotPasswordRequest represents a forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest represents a reset password request
type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8,max=128"`
}

// ChangePasswordRequest represents a change password request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// UpdateProfileRequest represents an update profile request
type UpdateProfileRequest struct {
	FirstName string `json:"first_name" validate:"required,min=1,max=100"`
	LastName  string `json:"last_name" validate:"required,min=1,max=100"`
}

// RefreshTokenRequest represents a refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// VerifyEmailRequest represents an email verification request
type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

// ResendVerificationRequest represents a resend verification email request
type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	User         UserProfile `json:"user"`
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	ExpiresIn    int64       `json:"expires_in"` // seconds
}

// ToProfile converts User to UserProfile
func (u *User) ToProfile() UserProfile {
	return UserProfile{
		ID:         u.ID,
		Email:      u.Email,
		FirstName:  u.FirstName,
		LastName:   u.LastName,
		IsVerified: u.IsVerified,
		CreatedAt:  u.CreatedAt,
	}
}

// IsLocked checks if the user account is currently locked
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// FullName returns the user's full name
func (u *User) FullName() string {
	return u.FirstName + " " + u.LastName
}
