package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/repository"
	"auth-service/internal/utils"
	"auth-service/pkg/auth"
	"auth-service/pkg/email"
	"auth-service/pkg/errors"
)

// AuthService defines the interface for authentication operations
type AuthService interface {
	// User registration and authentication
	SignUp(req *models.SignUpRequest) (*models.AuthResponse, error)
	SignIn(req *models.SignInRequest, ipAddress, userAgent string) (*models.AuthResponse, error)
	RefreshToken(refreshToken string) (*models.AuthResponse, error)

	// Password management
	ForgotPassword(req *models.ForgotPasswordRequest) error
	ResetPassword(req *models.ResetPasswordRequest) error
	ChangePassword(userID int64, req *models.ChangePasswordRequest) error

	// User profile management
	GetProfile(userID int64) (*models.UserProfile, error)
	UpdateProfile(userID int64, req *models.UpdateProfileRequest) (*models.UserProfile, error)

	// Token validation
	ValidateAccessToken(token string) (int64, error)
}

// authService implements AuthService interface
type authService struct {
	userRepo          repository.UserRepository
	tokenService      *auth.TokenService
	passwordValidator *utils.PasswordValidator
	emailService      email.EmailService
	bcryptCost        int
	maxLoginAttempts  int
	lockDuration      time.Duration
}

// AuthServiceConfig contains configuration for the auth service
type AuthServiceConfig struct {
	JWTSecret        string
	AccessExpiry     time.Duration
	RefreshExpiry    time.Duration
	BCryptCost       int
	MaxLoginAttempts int
	LockDuration     time.Duration
	EmailService     email.EmailService
}

// NewAuthService creates a new authentication service
func NewAuthService(userRepo repository.UserRepository, jwtSecret string, emailService email.EmailService) AuthService {
	return NewAuthServiceWithConfig(userRepo, AuthServiceConfig{
		JWTSecret:        jwtSecret,
		AccessExpiry:     15 * time.Minute,
		RefreshExpiry:    7 * 24 * time.Hour,
		BCryptCost:       12,
		MaxLoginAttempts: 5,
		LockDuration:     15 * time.Minute,
		EmailService:     emailService,
	})
}

// NewAuthServiceWithConfig creates a new authentication service with custom configuration
func NewAuthServiceWithConfig(userRepo repository.UserRepository, config AuthServiceConfig) AuthService {
	tokenService := auth.NewTokenService(config.JWTSecret, config.AccessExpiry, config.RefreshExpiry)
	passwordValidator := utils.NewPasswordValidator()

	return &authService{
		userRepo:          userRepo,
		tokenService:      tokenService,
		passwordValidator: passwordValidator,
		emailService:      config.EmailService,
		bcryptCost:        config.BCryptCost,
		maxLoginAttempts:  config.MaxLoginAttempts,
		lockDuration:      config.LockDuration,
	}
}

// SignUp registers a new user
func (s *authService) SignUp(req *models.SignUpRequest) (*models.AuthResponse, error) {
	// Sanitize input
	req.Email = strings.ToLower(utils.SanitizeInput(req.Email))
	req.FirstName = utils.SanitizeInput(req.FirstName)
	req.LastName = utils.SanitizeInput(req.LastName)

	// Validate email
	if err := utils.ValidateEmail(req.Email); err != nil {
		return nil, errors.ErrInvalidEmailError()
	}

	// Validate names
	if err := utils.ValidateName(req.FirstName, "first name"); err != nil {
		return nil, errors.NewAppError(errors.ErrValidation, err.Error(), 400)
	}

	if err := utils.ValidateName(req.LastName, "last name"); err != nil {
		return nil, errors.NewAppError(errors.ErrValidation, err.Error(), 400)
	}

	// Validate password
	if validationErrors := s.passwordValidator.ValidatePassword(req.Password); len(validationErrors) > 0 {
		details := make([]errors.ValidationErrorDetail, len(validationErrors))
		for i, err := range validationErrors {
			details[i] = errors.ValidationErrorDetail{
				Field:   err.Field,
				Message: err.Message,
			}
		}
		return nil, errors.NewValidationError("Password validation failed", details)
	}

	// Check if email already exists
	existingUser, err := s.userRepo.GetByEmail(req.Email)
	if err == nil && existingUser != nil {
		return nil, errors.ErrEmailExistsError()
	}

	// Hash password
	passwordHash, err := utils.HashPassword(req.Password, s.bcryptCost)
	if err != nil {
		return nil, errors.NewErrInternalError("failed to hash password")
	}

	// Create user
	user := &models.User{
		Email:        req.Email,
		PasswordHash: passwordHash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		IsVerified:   false, // In production, implement email verification
		IsActive:     true,
	}

	if err := s.userRepo.Create(user); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, errors.ErrEmailExistsError()
		}
		return nil, errors.NewErrDatabaseError("failed to create user")
	}

	// Generate tokens
	tokenPair, err := s.tokenService.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		return nil, errors.NewErrInternalError("failed to generate tokens")
	}

	// Send welcome email
	if s.emailService != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.emailService.SendWelcomeEmail(ctx, user.Email, user.FullName()); err != nil {
			// Log the error but don't fail the registration
			fmt.Printf("Failed to send welcome email to %s: %v\n", user.Email, err)
		}
	}

	return &models.AuthResponse{
		User:         user.ToProfile(),
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
	}, nil
}

// SignIn authenticates a user and returns tokens
func (s *authService) SignIn(req *models.SignInRequest, ipAddress, userAgent string) (*models.AuthResponse, error) {
	// Sanitize input
	req.Email = strings.ToLower(utils.SanitizeInput(req.Email))

	// Validate email format
	if err := utils.ValidateEmail(req.Email); err != nil {
		return nil, errors.ErrInvalidCredentialsError()
	}

	// Record login attempt
	loginAttempt := &models.LoginAttempt{
		Email:     req.Email,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   false,
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		// Record failed attempt
		s.userRepo.RecordLoginAttempt(loginAttempt)
		return nil, errors.ErrInvalidCredentialsError()
	}

	// Check if account is active
	if !user.IsActive {
		s.userRepo.RecordLoginAttempt(loginAttempt)
		return nil, errors.ErrAccountInactiveError()
	}

	// Check if account is locked
	if user.IsLocked() {
		s.userRepo.RecordLoginAttempt(loginAttempt)
		return nil, errors.ErrAccountLockedError(fmt.Sprintf("Account locked until %s", user.LockedUntil.Format(time.RFC3339)))
	}

	// Verify password
	if err := utils.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		// Increment failed login attempts
		user.FailedLoginAttempts++

		// Lock account if max attempts reached
		if user.FailedLoginAttempts >= s.maxLoginAttempts {
			lockUntil := time.Now().Add(s.lockDuration)
			if err := s.userRepo.LockAccount(user.ID, lockUntil); err == nil {
				user.LockedUntil = &lockUntil
			}
		} else {
			s.userRepo.UpdateFailedLoginAttempts(user.ID, user.FailedLoginAttempts)
		}

		// Record failed attempt
		s.userRepo.RecordLoginAttempt(loginAttempt)
		return nil, errors.ErrInvalidCredentialsError()
	}

	// Successful login - reset failed attempts if any
	if user.FailedLoginAttempts > 0 {
		s.userRepo.UpdateFailedLoginAttempts(user.ID, 0)
	}

	// Update last login
	s.userRepo.UpdateLastLogin(user.ID)

	// Record successful login attempt
	loginAttempt.Success = true
	s.userRepo.RecordLoginAttempt(loginAttempt)

	// Generate tokens
	tokenPair, err := s.tokenService.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		return nil, errors.NewErrInternalError("failed to generate tokens")
	}

	return &models.AuthResponse{
		User:         user.ToProfile(),
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
	}, nil
}

// RefreshToken generates new tokens using a refresh token
func (s *authService) RefreshToken(refreshToken string) (*models.AuthResponse, error) {
	// Validate refresh token and generate new tokens
	tokenPair, err := s.tokenService.RefreshAccessToken(refreshToken)
	if err != nil {
		return nil, errors.ErrTokenInvalidError()
	}

	// Get user details
	userID, err := s.tokenService.ExtractUserID(tokenPair.AccessToken)
	if err != nil {
		return nil, errors.ErrTokenInvalidError()
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, errors.ErrUserNotFoundError()
	}

	if !user.IsActive {
		return nil, errors.ErrAccountInactiveError()
	}

	return &models.AuthResponse{
		User:         user.ToProfile(),
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
	}, nil
}

// ForgotPassword initiates password reset process
func (s *authService) ForgotPassword(req *models.ForgotPasswordRequest) error {
	// Sanitize input
	req.Email = strings.ToLower(utils.SanitizeInput(req.Email))

	// Validate email format
	if err := utils.ValidateEmail(req.Email); err != nil {
		return errors.ErrInvalidEmailError()
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		// Don't reveal if email exists or not for security
		// But we still return nil to prevent email enumeration attacks
		return nil
	}

	// Check if user is active
	if !user.IsActive {
		// Don't reveal account status for security
		return nil
	}

	// Generate reset token
	token, err := utils.GeneratePasswordResetToken()
	if err != nil {
		return errors.NewErrInternalError("failed to generate reset token")
	}

	// Create password reset record
	passwordReset := &models.PasswordReset{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	if err := s.userRepo.CreatePasswordReset(passwordReset); err != nil {
		return errors.NewErrDatabaseError("failed to create password reset")
	}

	// Send password reset email
	if s.emailService != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.emailService.SendPasswordResetEmail(ctx, user.Email, token, user.FullName()); err != nil {
			// Log the error but don't fail the request
			// In production, you might want to use a proper logger here
			fmt.Printf("Failed to send password reset email to %s: %v\n", user.Email, err)
			// Don't return the error to prevent information disclosure
		}
	}

	return nil
}

// ResetPassword resets user password using reset token
func (s *authService) ResetPassword(req *models.ResetPasswordRequest) error {
	// Validate password
	if validationErrors := s.passwordValidator.ValidatePassword(req.Password); len(validationErrors) > 0 {
		details := make([]errors.ValidationErrorDetail, len(validationErrors))
		for i, err := range validationErrors {
			details[i] = errors.ValidationErrorDetail{
				Field:   err.Field,
				Message: err.Message,
			}
		}
		return errors.NewValidationError("Password validation failed", details)
	}

	// Get password reset record
	passwordReset, err := s.userRepo.GetPasswordReset(req.Token)
	if err != nil {
		return errors.ErrResetTokenInvalidError()
	}

	// Get user
	user, err := s.userRepo.GetByID(passwordReset.UserID)
	if err != nil {
		return errors.ErrUserNotFoundError()
	}

	// Hash new password
	passwordHash, err := utils.HashPassword(req.Password, s.bcryptCost)
	if err != nil {
		return errors.NewErrInternalError("failed to hash password")
	}

	// Update password
	user.PasswordHash = passwordHash
	if err := s.userRepo.Update(user); err != nil {
		return errors.NewErrDatabaseError("failed to update password")
	}

	// Mark reset token as used
	if err := s.userRepo.MarkPasswordResetUsed(req.Token); err != nil {
		// Log error but don't fail the operation
		fmt.Printf("Failed to mark password reset token as used: %v\n", err)
	}

	// Reset failed login attempts and unlock account
	if err := s.userRepo.UnlockAccount(user.ID); err != nil {
		// Log error but don't fail the operation
		fmt.Printf("Failed to unlock account after password reset: %v\n", err)
	}

	// Send password changed notification
	if s.emailService != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.emailService.SendPasswordChangedNotification(ctx, user.Email, user.FullName()); err != nil {
			// Log the error but don't fail the request
			fmt.Printf("Failed to send password changed notification to %s: %v\n", user.Email, err)
		}
	}

	return nil
}

// ChangePassword changes user password (requires current password)
func (s *authService) ChangePassword(userID int64, req *models.ChangePasswordRequest) error {
	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return errors.ErrUserNotFoundError()
	}

	// Verify current password
	if err := utils.VerifyPassword(req.CurrentPassword, user.PasswordHash); err != nil {
		return errors.ErrInvalidCredentialsError()
	}

	// Validate new password
	if validationErrors := s.passwordValidator.ValidatePassword(req.NewPassword); len(validationErrors) > 0 {
		details := make([]errors.ValidationErrorDetail, len(validationErrors))
		for i, err := range validationErrors {
			details[i] = errors.ValidationErrorDetail{
				Field:   err.Field,
				Message: err.Message,
			}
		}
		return errors.NewValidationError("Password validation failed", details)
	}

	// Hash new password
	passwordHash, err := utils.HashPassword(req.NewPassword, s.bcryptCost)
	if err != nil {
		return errors.NewErrInternalError("failed to hash password")
	}

	// Update password
	user.PasswordHash = passwordHash
	if err := s.userRepo.Update(user); err != nil {
		return errors.NewErrDatabaseError("failed to update password")
	}

	// Send password changed notification
	if s.emailService != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.emailService.SendPasswordChangedNotification(ctx, user.Email, user.FullName()); err != nil {
			// Log the error but don't fail the request
			fmt.Printf("Failed to send password changed notification to %s: %v\n", user.Email, err)
		}
	}

	return nil
}

// GetProfile retrieves user profile
func (s *authService) GetProfile(userID int64) (*models.UserProfile, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, errors.ErrUserNotFoundError()
	}

	profile := user.ToProfile()
	return &profile, nil
}

// UpdateProfile updates user profile
func (s *authService) UpdateProfile(userID int64, req *models.UpdateProfileRequest) (*models.UserProfile, error) {
	// Sanitize input
	req.FirstName = utils.SanitizeInput(req.FirstName)
	req.LastName = utils.SanitizeInput(req.LastName)

	// Validate names
	if err := utils.ValidateName(req.FirstName, "first name"); err != nil {
		return nil, errors.NewAppError(errors.ErrValidation, err.Error(), 400)
	}

	if err := utils.ValidateName(req.LastName, "last name"); err != nil {
		return nil, errors.NewAppError(errors.ErrValidation, err.Error(), 400)
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, errors.ErrUserNotFoundError()
	}

	// Update fields
	user.FirstName = req.FirstName
	user.LastName = req.LastName

	// Save changes
	if err := s.userRepo.Update(user); err != nil {
		return nil, errors.NewErrDatabaseError("failed to update profile")
	}

	profile := user.ToProfile()
	return &profile, nil
}

// ValidateAccessToken validates an access token and returns user ID
func (s *authService) ValidateAccessToken(token string) (int64, error) {
	userID, err := s.tokenService.ExtractUserID(token)
	if err != nil {
		return 0, errors.ErrTokenInvalidError()
	}

	// Verify user still exists and is active
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return 0, errors.ErrUserNotFoundError()
	}

	if !user.IsActive {
		return 0, errors.ErrAccountInactiveError()
	}

	return userID, nil
}
