package email

import (
	"context"
)

// EmailService defines the interface for sending emails
type EmailService interface {
	// SendPasswordResetEmail sends a password reset email to the user
	SendPasswordResetEmail(ctx context.Context, to, resetToken, userName string) error

	// SendWelcomeEmail sends a welcome email to newly registered users
	SendWelcomeEmail(ctx context.Context, to, userName string) error

	// SendAccountVerificationEmail sends account verification email
	SendAccountVerificationEmail(ctx context.Context, to, verificationToken, userName string) error

	// SendPasswordChangedNotification sends notification when password is changed
	SendPasswordChangedNotification(ctx context.Context, to, userName string) error

	// TestConnection tests the email service connection
	TestConnection() error
}

// EmailConfig contains configuration for email service
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
}

// EmailData represents the data needed for email templates
type EmailData struct {
	UserName           string
	ResetToken         string
	ResetURL           string
	VerificationToken  string
	VerificationURL    string
	CompanyName        string
	SupportEmail       string
	ResetExpiryMinutes int
}

// EmailTemplate represents an email template
type EmailTemplate struct {
	Subject     string
	HTMLContent string
	TextContent string
}
