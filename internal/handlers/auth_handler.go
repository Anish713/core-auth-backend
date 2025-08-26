package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/services"
	"auth-service/pkg/errors"
	"auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService    services.AuthService
	sessionManager services.SessionManager
	logger         logger.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService services.AuthService, sessionManager services.SessionManager, logger logger.Logger) *AuthHandler {
	return &AuthHandler{
		authService:    authService,
		sessionManager: sessionManager,
		logger:         logger,
	}
}

// SignUp handles user registration
// @Summary Register a new user
// @Description Register a new user with email, password, first name, and last name
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.SignUpRequest true "User registration data"
// @Success 201 {object} models.AuthSuccessResponse "User registered successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or validation errors"
// @Failure 409 {object} models.ErrorResponse "Email already exists"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/auth/signup [post]
func (h *AuthHandler) SignUp(c *gin.Context) {
	var req models.SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid signup request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	response, err := h.authService.SignUp(&req)
	if err != nil {
		h.logger.Error("Signup failed", "email", req.Email, "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Info("User signed up successfully", "user_id", response.User.ID, "email", response.User.Email)
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "User registered successfully",
		"data":    response,
	})
}

// SignIn handles user authentication
// @Summary Authenticate user
// @Description Authenticate user with email and password, returns access and refresh tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.SignInRequest true "User login credentials"
// @Success 200 {object} models.AuthSuccessResponse "Sign in successful"
// @Header 200 {string} X-Session-ID "Session ID for tracking user session"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or validation errors"
// @Failure 401 {object} models.ErrorResponse "Invalid credentials"
// @Failure 423 {object} models.ErrorResponse "Account locked due to too many failed attempts"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/auth/signin [post]
func (h *AuthHandler) SignIn(c *gin.Context) {
	var req models.SignInRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid signin request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	// Get client IP and user agent
	ipAddress := h.getClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	response, err := h.authService.SignIn(&req, ipAddress, userAgent)
	if err != nil {
		h.logger.Warn("Signin failed", "email", req.Email, "ip", ipAddress, "error", err.Error())
		h.handleError(c, err)
		return
	}

	// Create session if session manager is available
	if h.sessionManager != nil {
		h.logger.Info("Session manager available, creating session", "user_id", response.User.ID)
		ctx := c.Request.Context()
		sessionMetadata := map[string]interface{}{
			"ip_address": ipAddress,
			"user_agent": userAgent,
			"login_time": response.User.CreatedAt,
		}

		session, sessionErr := h.sessionManager.CreateSession(ctx, response.User.ID, response.User.Email, sessionMetadata)
		if sessionErr != nil {
			h.logger.Error("Failed to create session", "user_id", response.User.ID, "error", sessionErr.Error())
			// Don't fail the login, just log the error
		} else {
			h.logger.Info("Session created successfully", "user_id", response.User.ID, "session_id", session.ID)
			// Add session ID to response headers for client tracking
			c.Header("X-Session-ID", session.ID)
		}
	} else {
		h.logger.Warn("Session manager not available - Redis may not be connected")
	}

	h.logger.Info("User signed in successfully", "user_id", response.User.ID, "email", response.User.Email, "ip", ipAddress)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sign in successful",
		"data":    response,
	})
}

// RefreshToken handles token refresh
// @Summary Refresh access token
// @Description Refresh an access token using a valid refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.RefreshTokenRequest true "Refresh token data"
// @Success 200 {object} models.AuthSuccessResponse "Token refreshed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Invalid or expired refresh token"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid refresh token request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	response, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		h.logger.Warn("Token refresh failed", "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Info("Token refreshed successfully", "user_id", response.User.ID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Token refreshed successfully",
		"data":    response,
	})
}

// SignOut handles user sign out and session cleanup
// @Summary Sign out user
// @Description Sign out the authenticated user and invalidate current session
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param X-Session-ID header string false "Session ID to terminate"
// @Success 200 {object} models.SuccessResponse "Signed out successfully"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/auth/signout [post]
func (h *AuthHandler) SignOut(c *gin.Context) {
	userID := h.getUserID(c)
	if userID == 0 {
		h.handleError(c, errors.ErrUnauthorizedError())
		return
	}

	// Get session ID from header or query param
	sessionID := c.GetHeader("X-Session-ID")
	if sessionID == "" {
		sessionID = c.Query("session_id")
	}

	// Clean up session if session manager is available
	if h.sessionManager != nil && sessionID != "" {
		ctx := c.Request.Context()
		if err := h.sessionManager.DeleteSession(ctx, sessionID); err != nil {
			h.logger.Error("Failed to delete session", "user_id", userID, "session_id", sessionID, "error", err.Error())
		} else {
			h.logger.Info("Session deleted", "user_id", userID, "session_id", sessionID)
		}
	}

	// Add token to blacklist using session manager
	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if h.sessionManager != nil {
			ctx := c.Request.Context()
			// Blacklist token for remaining validity period (e.g., 24 hours)
			if err := h.sessionManager.BlacklistToken(ctx, token, time.Now().Add(24*time.Hour)); err != nil {
				h.logger.Error("Failed to blacklist token", "user_id", userID, "error", err.Error())
			}
		}
	}

	h.logger.Info("User signed out successfully", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Signed out successfully",
	})
}

// ForgotPassword handles password reset requests
// @Summary Request password reset
// @Description Send password reset email to the specified address
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.ForgotPasswordRequest true "Email address for password reset"
// @Success 200 {object} models.SuccessResponse "Password reset email sent (always returns success to prevent email enumeration)"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or email"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid forgot password request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	err := h.authService.ForgotPassword(&req)
	if err != nil {
		h.logger.Error("Forgot password failed", "email", req.Email, "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Info("Password reset requested", "email", req.Email)
	// Always return success to prevent email enumeration
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "If your email is registered, you will receive password reset instructions",
	})
}

// ResetPassword handles password reset
// @Summary Reset password using token
// @Description Reset user password using a valid reset token received via email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.ResetPasswordRequest true "Reset token and new password"
// @Success 200 {object} models.SuccessResponse "Password reset successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or validation errors"
// @Failure 404 {object} models.ErrorResponse "Invalid or expired reset token"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid reset password request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	err := h.authService.ResetPassword(&req)
	if err != nil {
		h.logger.Error("Password reset failed", "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Info("Password reset successfully")
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Password reset successfully",
	})
}

// ChangePassword handles password change requests
// @Summary Change user password
// @Description Change the authenticated user's password
// @Tags User Profile
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.ChangePasswordRequest true "Current and new password"
// @Success 200 {object} models.SuccessResponse "Password changed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or validation errors"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure 403 {object} models.ErrorResponse "Current password is incorrect"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/change-password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID := h.getUserID(c)
	if userID == 0 {
		h.handleError(c, errors.ErrUnauthorizedError())
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid change password request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	err := h.authService.ChangePassword(userID, &req)
	if err != nil {
		h.logger.Error("Change password failed", "user_id", userID, "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Info("Password changed successfully", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Password changed successfully",
	})
}

// GetProfile handles get user profile requests
// @Summary Get user profile
// @Description Get the authenticated user's profile information
// @Tags User Profile
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.ProfileSuccessResponse "Profile retrieved successfully"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/profile [get]
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID := h.getUserID(c)
	if userID == 0 {
		h.handleError(c, errors.ErrUnauthorizedError())
		return
	}

	profile, err := h.authService.GetProfile(userID)
	if err != nil {
		h.logger.Error("Get profile failed", "user_id", userID, "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Debug("Profile retrieved", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    profile,
	})
}

// UpdateProfile handles update user profile requests
// @Summary Update user profile
// @Description Update the authenticated user's profile information
// @Tags User Profile
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.UpdateProfileRequest true "Updated profile information"
// @Success 200 {object} models.ProfileSuccessResponse "Profile updated successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or validation errors"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/profile [put]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID := h.getUserID(c)
	if userID == 0 {
		h.handleError(c, errors.ErrUnauthorizedError())
		return
	}

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid update profile request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	profile, err := h.authService.UpdateProfile(userID, &req)
	if err != nil {
		h.logger.Error("Update profile failed", "user_id", userID, "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Info("Profile updated successfully", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Profile updated successfully",
		"data":    profile,
	})
}

// GetActiveSessions returns active sessions for the current user
// @Summary Get active sessions
// @Description Get all active sessions for the authenticated user
// @Tags Session Management
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SessionsSuccessResponse "Sessions retrieved successfully"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure 501 {object} models.ErrorResponse "Session management not available"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/sessions [get]
func (h *AuthHandler) GetActiveSessions(c *gin.Context) {
	userID := h.getUserID(c)
	if userID == 0 {
		h.handleError(c, errors.ErrUnauthorizedError())
		return
	}

	if h.sessionManager == nil {
		h.handleError(c, errors.NewAppError(errors.ErrNotImplemented, "Session management not available", http.StatusNotImplemented))
		return
	}

	ctx := c.Request.Context()
	sessions, err := h.sessionManager.GetUserSessions(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get user sessions", "user_id", userID, "error", err.Error())
		h.handleError(c, errors.NewErrInternalError("Failed to retrieve sessions"))
		return
	}

	h.logger.Debug("Sessions retrieved", "user_id", userID, "count", len(sessions))
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"sessions": sessions,
			"count":    len(sessions),
		},
	})
}

// TerminateSession terminates a specific session
// @Summary Terminate specific session
// @Description Terminate a specific session by session ID
// @Tags Session Management
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param sessionId path string true "Session ID to terminate"
// @Success 200 {object} models.SuccessResponse "Session terminated successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid session ID"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure 403 {object} models.ErrorResponse "Not authorized to terminate this session"
// @Failure 404 {object} models.ErrorResponse "Session not found"
// @Failure 501 {object} models.ErrorResponse "Session management not available"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/sessions/{sessionId} [delete]
func (h *AuthHandler) TerminateSession(c *gin.Context) {
	userID := h.getUserID(c)
	if userID == 0 {
		h.handleError(c, errors.ErrUnauthorizedError())
		return
	}

	if h.sessionManager == nil {
		h.handleError(c, errors.NewAppError(errors.ErrNotImplemented, "Session management not available", http.StatusNotImplemented))
		return
	}

	sessionID := c.Param("sessionId")
	if sessionID == "" {
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Session ID is required", http.StatusBadRequest))
		return
	}

	ctx := c.Request.Context()
	// Verify the session belongs to the user
	session, err := h.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		h.logger.Error("Session not found", "session_id", sessionID, "user_id", userID, "error", err.Error())
		h.handleError(c, errors.ErrNotFoundError("Session not found"))
		return
	}

	if session.UserID != userID {
		h.logger.Warn("Unauthorized session termination attempt", "session_id", sessionID, "session_user_id", session.UserID, "requesting_user_id", userID)
		h.handleError(c, errors.ErrForbiddenError("Not authorized to terminate this session"))
		return
	}

	if err := h.sessionManager.DeleteSession(ctx, sessionID); err != nil {
		h.logger.Error("Failed to terminate session", "session_id", sessionID, "user_id", userID, "error", err.Error())
		h.handleError(c, errors.NewErrInternalError("Failed to terminate session"))
		return
	}

	h.logger.Info("Session terminated", "session_id", sessionID, "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Session terminated successfully",
	})
}

// TerminateAllSessions terminates all sessions for the current user except the current one
// @Summary Terminate all sessions
// @Description Terminate all sessions for the authenticated user except the current one
// @Tags Session Management
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param X-Session-ID header string false "Current session ID to preserve"
// @Success 200 {object} models.SuccessResponse "All sessions terminated successfully"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure 501 {object} models.ErrorResponse "Session management not available"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/sessions [delete]
func (h *AuthHandler) TerminateAllSessions(c *gin.Context) {
	userID := h.getUserID(c)
	if userID == 0 {
		h.handleError(c, errors.ErrUnauthorizedError())
		return
	}

	if h.sessionManager == nil {
		h.handleError(c, errors.NewAppError(errors.ErrNotImplemented, "Session management not available", http.StatusNotImplemented))
		return
	}

	// Get current session ID to preserve it
	currentSessionID := c.GetHeader("X-Session-ID")

	ctx := c.Request.Context()
	var err error

	if currentSessionID != "" {
		// Terminate all sessions except the current one
		err = h.sessionManager.DeleteAllUserSessionsExcept(ctx, userID, currentSessionID)
	} else {
		// Terminate all sessions if no current session ID
		err = h.sessionManager.DeleteUserSessions(ctx, userID)
	}

	if err != nil {
		h.logger.Error("Failed to terminate user sessions", "user_id", userID, "error", err.Error())
		h.handleError(c, errors.NewErrInternalError("Failed to terminate sessions"))
		return
	}

	h.logger.Info("All user sessions terminated", "user_id", userID, "preserved_session", currentSessionID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "All sessions terminated successfully",
	})
}

// Helper methods

// handleError handles application errors and returns appropriate HTTP responses
func (h *AuthHandler) handleError(c *gin.Context, err error) {
	if appErr := errors.GetAppError(err); appErr != nil {
		// Check if it's a validation error
		if validationErr, ok := err.(*errors.ValidationError); ok {
			c.JSON(appErr.StatusCode, gin.H{
				"success": false,
				"error": gin.H{
					"code":    appErr.Code,
					"message": appErr.Message,
					"details": validationErr.Errors,
				},
			})
			return
		}

		// Regular app error
		response := gin.H{
			"success": false,
			"error": gin.H{
				"code":    appErr.Code,
				"message": appErr.Message,
			},
		}

		// Include details only in development
		if appErr.Details != "" {
			response["error"].(gin.H)["details"] = appErr.Details
		}

		c.JSON(appErr.StatusCode, response)
		return
	}

	// Fallback for unknown errors
	h.logger.Error("Unknown error occurred", "error", err.Error())
	c.JSON(http.StatusInternalServerError, gin.H{
		"success": false,
		"error": gin.H{
			"code":    errors.ErrInternal,
			"message": "Internal server error",
		},
	})
}

// getUserID extracts user ID from context (set by auth middleware)
func (h *AuthHandler) getUserID(c *gin.Context) int64 {
	userIDStr, exists := c.Get("user_id")
	if !exists {
		return 0
	}

	if userID, ok := userIDStr.(int64); ok {
		return userID
	}

	// Try to parse as string
	if userIDStr, ok := userIDStr.(string); ok {
		if userID, err := strconv.ParseInt(userIDStr, 10, 64); err == nil {
			return userID
		}
	}

	return 0
}

// getClientIP extracts the real client IP address
func (h *AuthHandler) getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header first
	xff := c.GetHeader("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	xri := c.GetHeader("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return c.ClientIP()
}

// VerifyEmail handles email verification
// @Summary Verify email address
// @Description Verify user email address using verification token received via email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.VerifyEmailRequest true "Email verification token"
// @Success 200 {object} models.SuccessResponse "Email verified successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or validation errors"
// @Failure 404 {object} models.ErrorResponse "Invalid or expired verification token"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req models.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid verify email request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	err := h.authService.VerifyEmail(&req)
	if err != nil {
		h.logger.Error("Email verification failed", "token", req.Token, "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Info("Email verified successfully", "token", req.Token)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Email verified successfully. You can now sign in to your account.",
	})
}

// ResendVerificationEmail handles resending verification email
// @Summary Resend email verification
// @Description Resend verification email to the specified address
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.ResendVerificationRequest true "Email address for resending verification"
// @Success 200 {object} models.SuccessResponse "Verification email resent (always returns success to prevent email enumeration)"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or email"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/auth/resend-verification [post]
func (h *AuthHandler) ResendVerificationEmail(c *gin.Context) {
	var req models.ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid resend verification request", "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	err := h.authService.ResendVerificationEmail(&req)
	if err != nil {
		h.logger.Error("Resend verification failed", "email", req.Email, "error", err.Error())
		h.handleError(c, err)
		return
	}

	h.logger.Info("Verification email resent", "email", req.Email)
	// Always return success to prevent email enumeration
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "If your email is registered and not yet verified, you will receive a new verification email",
	})
}

// DeleteAccount handles user account deletion
// @Summary Delete user account
// @Description Permanently delete the authenticated user's account
// @Tags User Profile
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.DeleteAccountRequest true "Password confirmation and optional reason"
// @Success 200 {object} models.SuccessResponse "Account deleted successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request format or validation errors"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure 403 {object} models.ErrorResponse "Incorrect password"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/account [delete]
func (h *AuthHandler) DeleteAccount(c *gin.Context) {
	userID := h.getUserID(c)
	if userID == 0 {
		h.handleError(c, errors.ErrUnauthorizedError())
		return
	}

	var req models.DeleteAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid delete account request", "user_id", userID, "error", err.Error())
		h.handleError(c, errors.NewAppError(errors.ErrValidation, "Invalid request format", http.StatusBadRequest))
		return
	}

	err := h.authService.DeleteAccount(userID, &req)
	if err != nil {
		h.logger.Error("Account deletion failed", "user_id", userID, "error", err.Error())
		h.handleError(c, err)
		return
	}

	// Clean up all user sessions if session manager is available
	if h.sessionManager != nil {
		ctx := c.Request.Context()
		if sessionErr := h.sessionManager.DeleteUserSessions(ctx, userID); sessionErr != nil {
			h.logger.Error("Failed to cleanup sessions after account deletion", "user_id", userID, "error", sessionErr.Error())
			// Don't fail the deletion for this
		}
	}

	// Blacklist current token if available
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if h.sessionManager != nil {
			ctx := c.Request.Context()
			// Blacklist token for extended period
			if err := h.sessionManager.BlacklistToken(ctx, token, time.Now().Add(7*24*time.Hour)); err != nil {
				h.logger.Error("Failed to blacklist token after account deletion", "user_id", userID, "error", err.Error())
			}
		}
	}

	h.logger.Info("Account deleted successfully", "user_id", userID, "reason", req.Reason)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Your account has been successfully deleted. Thank you for using our service.",
	})
}
