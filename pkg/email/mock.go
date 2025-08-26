package email

import (
	"context"
	"fmt"
	"log"
)

// mockEmailService implements EmailService for development/testing
type mockEmailService struct {
	logger func(string, ...interface{})
}

// NewMockEmailService creates a new mock email service
func NewMockEmailService() EmailService {
	return &mockEmailService{
		logger: func(format string, args ...interface{}) {
			log.Printf("[MOCK EMAIL] "+format, args...)
		},
	}
}

// SendPasswordResetEmail logs the password reset email instead of sending it
func (m *mockEmailService) SendPasswordResetEmail(ctx context.Context, to, resetToken, userName string) error {
	m.logger("Password Reset Email - To: %s, User: %s, Token: %s", to, userName, resetToken)
	m.logger("Reset URL: https://yourapp.com/reset-password?token=%s", resetToken)
	return nil
}

// SendWelcomeEmail logs the welcome email instead of sending it
func (m *mockEmailService) SendWelcomeEmail(ctx context.Context, to, userName string) error {
	m.logger("Welcome Email - To: %s, User: %s", to, userName)
	return nil
}

// SendAccountVerificationEmail logs the verification email instead of sending it
func (m *mockEmailService) SendAccountVerificationEmail(ctx context.Context, to, verificationToken, userName string) error {
	m.logger("Account Verification Email - To: %s, User: %s, Token: %s", to, userName, verificationToken)
	m.logger("Verification URL: https://yourapp.com/verify?token=%s", verificationToken)
	return nil
}

// SendPasswordChangedNotification logs the password changed notification instead of sending it
func (m *mockEmailService) SendPasswordChangedNotification(ctx context.Context, to, userName string) error {
	m.logger("Password Changed Notification - To: %s, User: %s", to, userName)
	return nil
}

// TestConnection always returns success for mock service
func (m *mockEmailService) TestConnection() error {
	m.logger("Mock email service connection test - Always successful")
	return nil
}

// NewEmailService creates the appropriate email service based on environment
func NewEmailService(config EmailConfig, isDevelopment bool) (EmailService, error) {
	if isDevelopment || config.SMTPHost == "" {
		return NewMockEmailService(), nil
	}

	// Validate configuration
	if config.SMTPHost == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if config.SMTPPort == 0 {
		return nil, fmt.Errorf("SMTP port is required")
	}
	if config.FromEmail == "" {
		return nil, fmt.Errorf("from email is required")
	}

	service := NewSMTPEmailService(config)

	// Test connection
	if err := service.TestConnection(); err != nil {
		return nil, fmt.Errorf("failed to connect to email service: %w", err)
	}

	return service, nil
}
