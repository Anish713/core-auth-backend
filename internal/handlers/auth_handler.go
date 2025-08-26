package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"auth-service/internal/models"
	"auth-service/internal/services"
	"auth-service/pkg/errors"
	"auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService services.AuthService
	logger      logger.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService services.AuthService, logger logger.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

// SignUp handles user registration
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

	h.logger.Info("User signed in successfully", "user_id", response.User.ID, "email", response.User.Email, "ip", ipAddress)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sign in successful",
		"data":    response,
	})
}

// RefreshToken handles token refresh
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

// ForgotPassword handles password reset requests
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
