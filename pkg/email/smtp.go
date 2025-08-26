package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strconv"
	"time"
)

// smtpEmailService implements EmailService using SMTP
type smtpEmailService struct {
	config    EmailConfig
	auth      smtp.Auth
	addr      string
	templates map[string]*EmailTemplate
}

// NewSMTPEmailService creates a new SMTP email service
func NewSMTPEmailService(config EmailConfig) EmailService {
	auth := smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost)
	addr := config.SMTPHost + ":" + strconv.Itoa(config.SMTPPort)

	service := &smtpEmailService{
		config:    config,
		auth:      auth,
		addr:      addr,
		templates: make(map[string]*EmailTemplate),
	}

	// Initialize default templates
	service.initializeTemplates()

	return service
}

// initializeTemplates sets up default email templates
func (s *smtpEmailService) initializeTemplates() {
	s.templates["password_reset"] = &EmailTemplate{
		Subject: "Password Reset Request",
		HTMLContent: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background-color: #007bff; color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -20px -20px 20px -20px; }
        .content { padding: 20px 0; }
        .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { text-align: center; font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px; }
        .token-box { background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 10px; font-family: monospace; word-break: break-all; margin: 10px 0; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 10px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset</h1>
        </div>
        <div class="content">
            <h2>Hello {{.UserName}},</h2>
            <p>We received a request to reset your password. If you didn't make this request, you can safely ignore this email.</p>
            
            <p>To reset your password, use the following token:</p>
            <div class="token-box">{{.ResetToken}}</div>
            
            <p>Or click the button below:</p>
            <a href="{{.ResetURL}}" class="button">Reset Password</a>
            
            <div class="warning">
                <strong>Important:</strong> This password reset token will expire in {{.ResetExpiryMinutes}} minutes for your security.
            </div>
            
            <p>If you're having trouble with the button above, copy and paste the following URL into your web browser:</p>
            <p style="word-break: break-all; color: #007bff;">{{.ResetURL}}</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>{{.CompanyName}} Team</p>
            <p>If you have any questions, contact us at {{.SupportEmail}}</p>
            <p>This is an automated message, please don't reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextContent: `Hello {{.UserName}},

We received a request to reset your password. If you didn't make this request, you can safely ignore this email.

To reset your password, use the following token:
{{.ResetToken}}

Or visit this URL:
{{.ResetURL}}

Important: This password reset token will expire in {{.ResetExpiryMinutes}} minutes for your security.

Best regards,
{{.CompanyName}} Team

If you have any questions, contact us at {{.SupportEmail}}
This is an automated message, please don't reply to this email.`,
	}

	s.templates["welcome"] = &EmailTemplate{
		Subject: "Welcome to {{.CompanyName}}!",
		HTMLContent: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background-color: #28a745; color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -20px -20px 20px -20px; }
        .content { padding: 20px 0; }
        .footer { text-align: center; font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to {{.CompanyName}}!</h1>
        </div>
        <div class="content">
            <h2>Hello {{.UserName}},</h2>
            <p>Welcome to {{.CompanyName}}! We're excited to have you on board.</p>
            <p>Your account has been successfully created and you can now access all our features.</p>
            <p>If you have any questions or need help getting started, don't hesitate to reach out to our support team.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>{{.CompanyName}} Team</p>
            <p>If you have any questions, contact us at {{.SupportEmail}}</p>
        </div>
    </div>
</body>
</html>`,
		TextContent: `Hello {{.UserName}},

Welcome to {{.CompanyName}}! We're excited to have you on board.

Your account has been successfully created and you can now access all our features.

If you have any questions or need help getting started, don't hesitate to reach out to our support team.

Best regards,
{{.CompanyName}} Team

If you have any questions, contact us at {{.SupportEmail}}`,
	}

	s.templates["password_changed"] = &EmailTemplate{
		Subject: "Password Changed Successfully",
		HTMLContent: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background-color: #28a745; color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -20px -20px 20px -20px; }
        .content { padding: 20px 0; }
        .footer { text-align: center; font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px; }
        .security-notice { background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 10px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Changed</h1>
        </div>
        <div class="content">
            <h2>Hello {{.UserName}},</h2>
            <p>This is a confirmation that your password has been successfully changed.</p>
            
            <div class="security-notice">
                <strong>Security Notice:</strong> If you didn't make this change, please contact our support team immediately at {{.SupportEmail}}.
            </div>
            
            <p>For your security, we recommend:</p>
            <ul>
                <li>Using a strong, unique password</li>
                <li>Not sharing your password with anyone</li>
                <li>Signing out from all devices if you suspect unauthorized access</li>
            </ul>
        </div>
        <div class="footer">
            <p>Best regards,<br>{{.CompanyName}} Team</p>
            <p>If you have any questions, contact us at {{.SupportEmail}}</p>
        </div>
    </div>
</body>
</html>`,
		TextContent: `Hello {{.UserName}},

This is a confirmation that your password has been successfully changed.

Security Notice: If you didn't make this change, please contact our support team immediately at {{.SupportEmail}}.

For your security, we recommend:
- Using a strong, unique password
- Not sharing your password with anyone
- Signing out from all devices if you suspect unauthorized access

Best regards,
{{.CompanyName}} Team

If you have any questions, contact us at {{.SupportEmail}}`,
	}

	s.templates["email_verification"] = &EmailTemplate{
		Subject: "Verify Your Email Address - {{.CompanyName}}",
		HTMLContent: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background-color: #007bff; color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -20px -20px 20px -20px; }
        .content { padding: 20px 0; }
        .footer { text-align: center; font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
        .token-box { background-color: #f8f9fa; border: 2px dashed #6c757d; padding: 15px; font-family: monospace; font-size: 16px; text-align: center; margin: 20px 0; word-break: break-all; }
        .info { background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 10px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verify Your Email</h1>
        </div>
        <div class="content">
            <h2>Hello {{.UserName}},</h2>
            <p>Thank you for signing up with {{.CompanyName}}! To complete your registration and start using your account, please verify your email address.</p>
            
            <p>You can verify your email by clicking the button below:</p>
            <div style="text-align: center;">
                <a href="{{.VerificationURL}}" class="button">Verify Email Address</a>
            </div>
            
            <p>Or use this verification token:</p>
            <div class="token-box">{{.VerificationToken}}</div>
            
            <div class="info">
                <strong>Important:</strong> This verification link will expire in 24 hours for security reasons. If you don't verify your email within this time, you may need to request a new verification email.
            </div>
            
            <p>If you're having trouble with the button above, copy and paste the following URL into your web browser:</p>
            <p style="word-break: break-all; color: #007bff;">{{.VerificationURL}}</p>
            
            <p>If you didn't create an account with {{.CompanyName}}, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>{{.CompanyName}} Team</p>
            <p>If you have any questions, contact us at {{.SupportEmail}}</p>
            <p>This is an automated message, please don't reply to this email.</p>
        </div>
    </div>
</body>
</html>`,
		TextContent: `Hello {{.UserName}},

Thank you for signing up with {{.CompanyName}}! To complete your registration and start using your account, please verify your email address.

Verification Token: {{.VerificationToken}}

Verification URL: {{.VerificationURL}}

Important: This verification link will expire in 24 hours for security reasons. If you don't verify your email within this time, you may need to request a new verification email.

If you didn't create an account with {{.CompanyName}}, you can safely ignore this email.

Best regards,
{{.CompanyName}} Team

If you have any questions, contact us at {{.SupportEmail}}
This is an automated message, please don't reply to this email.`,
	}
}

// SendPasswordResetEmail sends a password reset email
func (s *smtpEmailService) SendPasswordResetEmail(ctx context.Context, to, resetToken, userName string) error {
	data := EmailData{
		UserName:           userName,
		ResetToken:         resetToken,
		ResetURL:           fmt.Sprintf("https://yourapp.com/reset-password?token=%s", resetToken),
		CompanyName:        "Auth Service",
		SupportEmail:       s.config.FromEmail,
		ResetExpiryMinutes: 60, // 1 hour
	}

	return s.sendTemplatedEmail(ctx, "password_reset", to, data)
}

// SendWelcomeEmail sends a welcome email
func (s *smtpEmailService) SendWelcomeEmail(ctx context.Context, to, userName string) error {
	data := EmailData{
		UserName:     userName,
		CompanyName:  "Auth Service",
		SupportEmail: s.config.FromEmail,
	}

	return s.sendTemplatedEmail(ctx, "welcome", to, data)
}

// SendAccountVerificationEmail sends account verification email
func (s *smtpEmailService) SendAccountVerificationEmail(ctx context.Context, to, verificationToken, userName string) error {
	data := EmailData{
		UserName:          userName,
		VerificationToken: verificationToken,
		VerificationURL:   fmt.Sprintf("https://yourapp.com/verify?token=%s", verificationToken),
		CompanyName:       "Auth Service",
		SupportEmail:      s.config.FromEmail,
	}

	return s.sendTemplatedEmail(ctx, "email_verification", to, data)
}

// SendPasswordChangedNotification sends password changed notification
func (s *smtpEmailService) SendPasswordChangedNotification(ctx context.Context, to, userName string) error {
	data := EmailData{
		UserName:     userName,
		CompanyName:  "Auth Service",
		SupportEmail: s.config.FromEmail,
	}

	return s.sendTemplatedEmail(ctx, "password_changed", to, data)
}

// TestConnection tests the SMTP connection
func (s *smtpEmailService) TestConnection() error {
	// Try to connect to SMTP server
	client, err := smtp.Dial(s.addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer client.Close()

	// Start TLS for secure connection (required for Gmail)
	if err := client.StartTLS(&tls.Config{ServerName: s.config.SMTPHost}); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}

	// Test authentication if credentials are provided
	if s.config.SMTPUsername != "" && s.config.SMTPPassword != "" {
		if err := client.Auth(s.auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	return nil
}

// sendTemplatedEmail sends an email using a template
func (s *smtpEmailService) sendTemplatedEmail(ctx context.Context, templateName, to string, data EmailData) error {
	template, exists := s.templates[templateName]
	if !exists {
		return fmt.Errorf("email template '%s' not found", templateName)
	}

	// Parse and execute HTML template
	htmlTmpl, err := template.Parse(template.HTMLContent)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	var htmlBody bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBody, data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	// Parse and execute text template
	textTmpl, err := template.Parse(template.TextContent)
	if err != nil {
		return fmt.Errorf("failed to parse text template: %w", err)
	}

	var textBody bytes.Buffer
	if err := textTmpl.Execute(&textBody, data); err != nil {
		return fmt.Errorf("failed to execute text template: %w", err)
	}

	// Parse and execute subject template
	subjectTmpl, err := template.Parse(template.Subject)
	if err != nil {
		return fmt.Errorf("failed to parse subject template: %w", err)
	}

	var subjectBuffer bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuffer, data); err != nil {
		return fmt.Errorf("failed to execute subject template: %w", err)
	}

	subject := subjectBuffer.String()

	// Create email message
	msg := s.createMultipartMessage(s.config.FromEmail, to, subject, textBody.String(), htmlBody.String())

	// Send email with timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- smtp.SendMail(s.addr, s.auth, s.config.FromEmail, []string{to}, []byte(msg))
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return fmt.Errorf("failed to send email: %w", err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("email sending timeout: %w", ctx.Err())
	}
}

// createMultipartMessage creates a multipart email message
func (s *smtpEmailService) createMultipartMessage(from, to, subject, textBody, htmlBody string) string {
	boundary := "boundary-" + strconv.FormatInt(time.Now().Unix(), 16)
	fromName := s.config.FromName
	if fromName == "" {
		fromName = "Auth Service"
	}

	msg := fmt.Sprintf("From: %s <%s>\r\n", fromName, from)
	msg += fmt.Sprintf("To: %s\r\n", to)
	msg += fmt.Sprintf("Subject: %s\r\n", subject)
	msg += "MIME-Version: 1.0\r\n"
	msg += fmt.Sprintf("Content-Type: multipart/alternative; boundary=%s\r\n", boundary)
	msg += "\r\n"

	// Text part
	msg += fmt.Sprintf("--%s\r\n", boundary)
	msg += "Content-Type: text/plain; charset=utf-8\r\n"
	msg += "Content-Transfer-Encoding: 7bit\r\n"
	msg += "\r\n"
	msg += textBody + "\r\n"

	// HTML part
	msg += fmt.Sprintf("--%s\r\n", boundary)
	msg += "Content-Type: text/html; charset=utf-8\r\n"
	msg += "Content-Transfer-Encoding: 7bit\r\n"
	msg += "\r\n"
	msg += htmlBody + "\r\n"

	// End boundary
	msg += fmt.Sprintf("--%s--\r\n", boundary)

	return msg
}

// Helper function to create template
func (tmpl *EmailTemplate) Parse(content string) (*template.Template, error) {
	return template.New("email").Parse(content)
}
