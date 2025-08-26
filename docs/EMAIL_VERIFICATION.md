# Email Verification Implementation

This document describes the email verification system implemented in the authentication service.

## Overview

The email verification system ensures that users verify their email addresses before they can fully access the application. This feature includes:

- **Signup Email Verification**: Users must verify their email before they can sign in
- **Configurable Email Notifications**: Welcome emails and password change notifications can be enabled/disabled
- **Secure Token-based Verification**: Uses cryptographically secure 64-character tokens
- **Time-based Expiry**: Verification tokens expire after 24 hours (configurable)

## Configuration

### Environment Variables

Add these variables to your `.env` file:

```bash
# Email Verification Configuration
EMAIL_VERIFICATION_ENABLED=true
EMAIL_VERIFICATION_EXPIRY=24h

# Email Notification Configuration
SEND_WELCOME_EMAIL=true
SEND_PASSWORD_CHANGED_EMAIL=true
```

### Configuration Options

- `EMAIL_VERIFICATION_ENABLED`: Enable/disable email verification requirement (default: true)
- `EMAIL_VERIFICATION_EXPIRY`: How long verification tokens are valid (default: 24h)
- `SEND_WELCOME_EMAIL`: Send welcome email after successful verification (default: true)
- `SEND_PASSWORD_CHANGED_EMAIL`: Send notification when password is changed (default: true)

## API Endpoints

### 1. Sign Up with Email Verification

**Endpoint**: `POST /api/v1/auth/signup`

**Request**:

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response** (when email verification is enabled):

```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "is_verified": false,
      "created_at": "2024-01-15T10:30:00Z"
    },
    "access_token": "",
    "refresh_token": "",
    "expires_in": 0
  }
}
```

**Note**: No tokens are provided until email is verified.

### 2. Verify Email

**Endpoint**: `POST /api/v1/auth/verify-email`

**Request**:

```json
{
  "token": "64-character-verification-token"
}
```

**Response**:

```json
{
  "success": true,
  "message": "Email verified successfully. You can now sign in to your account."
}
```

### 3. Resend Verification Email

**Endpoint**: `POST /api/v1/auth/resend-verification`

**Request**:

```json
{
  "email": "user@example.com"
}
```

**Response**:

```json
{
  "success": true,
  "message": "If your email is registered and not yet verified, you will receive a new verification email"
}
```

### 4. Sign In (After Verification)

**Endpoint**: `POST /api/v1/auth/signin`

**Behavior**:

- **Unverified users**: Returns 403 Forbidden with message "Please verify your email address before signing in"
- **Verified users**: Returns normal response with tokens

## Email Templates

### Verification Email

- **Subject**: "Verify Your Email Address - Auth Service"
- **Content**: Contains verification token and clickable link
- **Expiry**: Shows token expiration time (24 hours by default)

### Welcome Email

- **Subject**: "Welcome to Auth Service!"
- **When sent**: After successful email verification (if `SEND_WELCOME_EMAIL=true`)
- **Content**: Welcome message with account confirmation

### Password Change Notification

- **Subject**: "Password Changed Successfully"
- **When sent**: After password reset or change (if `SEND_PASSWORD_CHANGED_EMAIL=true`)
- **Content**: Security notice about password change

## Database Schema

### email_verifications Table

```sql
CREATE TABLE email_verifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Indexes**:

- `idx_email_verifications_token` on `token`
- `idx_email_verifications_expires_at` on `expires_at`
- `idx_email_verifications_user_id` on `user_id`

## Security Features

1. **Cryptographically Secure Tokens**: Uses `crypto/rand` for token generation
2. **Single-Use Tokens**: Tokens are marked as used after verification
3. **Time-based Expiry**: Tokens automatically expire after configured duration
4. **Email Enumeration Protection**: Consistent responses regardless of email existence
5. **Rate Limiting**: Subject to API rate limiting like other endpoints

## Development vs Production

### Development Mode

- Emails are logged to console (mock email service)
- Verification tokens visible in server logs
- Useful for testing and debugging

### Production Mode

- Real emails sent via SMTP (Gmail configuration provided)
- Tokens not logged for security
- Requires proper SMTP configuration

## Testing the Implementation

### 1. Test Signup Flow

```bash
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPassword123!","first_name":"Test","last_name":"User"}'
```

### 2. Check Server Logs for Verification Token

Look for: `[MOCK EMAIL] Account Verification Email - To: test@example.com, User: Test User, Token: ...`

### 3. Test Email Verification

```bash
curl -X POST http://localhost:8080/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token":"your-verification-token-here"}'
```

### 4. Test Signin After Verification

```bash
curl -X POST http://localhost:8080/api/v1/auth/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPassword123!"}'
```

## Best Practices

1. **Always enable email verification in production**
2. **Set appropriate token expiry times** (24h is recommended)
3. **Monitor failed verification attempts** for potential abuse
4. **Implement proper email deliverability** (SPF, DKIM, DMARC)
5. **Provide clear user instructions** in verification emails
6. **Handle email bounces gracefully**
7. **Consider implementing email change verification** for profile updates

## Troubleshooting

### Common Issues

1. **Verification token not found**

   - Check if database migrations were applied
   - Verify token hasn't expired
   - Ensure token is exactly as provided (no extra characters)

2. **Emails not being sent**

   - Check SMTP configuration
   - Verify email service initialization
   - Check server logs for email sending errors

3. **User can't sign in after verification**
   - Verify `is_verified` field in database is true
   - Check if email verification is actually enabled
   - Ensure user account is active

### Debugging

- Check server logs for detailed error messages
- Verify database state directly if needed
- Use curl commands to test API endpoints
- Enable debug logging for email service in development
