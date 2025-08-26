package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"auth-service/pkg/auth"
	"auth-service/pkg/errors"
	"auth-service/pkg/logger"
	"auth-service/pkg/ratelimit"

	"github.com/gin-gonic/gin"
)

// Logger middleware for request logging
func Logger(log logger.Logger) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		log.Info("Request processed",
			"method", param.Method,
			"path", param.Path,
			"status", param.StatusCode,
			"latency", param.Latency,
			"ip", param.ClientIP,
			"user_agent", param.Request.UserAgent(),
		)
		return ""
	})
}

// Recovery middleware for panic recovery
func Recovery(log logger.Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		log.Error("Panic recovered",
			"error", recovered,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"ip", c.ClientIP(),
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": gin.H{
				"code":    errors.ErrInternal,
				"message": "Internal server error",
			},
		})
	})
}

// CORS middleware for cross-origin requests
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow specific origins or all origins in development
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:3001",
			"http://localhost:8080",
			"https://yourdomain.com",
		}

		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}

		if allowed || origin == "" {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent XSS attacks
		c.Header("X-XSS-Protection", "1; mode=block")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Prevent framing (clickjacking protection)
		c.Header("X-Frame-Options", "DENY")

		// Strict Transport Security (HTTPS only)
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'")

		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy (formerly Feature Policy)
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		c.Next()
	}
}

// AuthRequired middleware for protected routes
func AuthRequired(jwtSecret string) gin.HandlerFunc {
	return AuthRequiredWithSessionManager(jwtSecret, nil)
}

// AuthRequiredWithSessionManager middleware for protected routes with session management
func AuthRequiredWithSessionManager(jwtSecret string, sessionManager interface{}) gin.HandlerFunc {
	tokenService := auth.NewTokenService(jwtSecret, 15*time.Minute, 7*24*time.Hour)

	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    errors.ErrUnauthorized,
					"message": "Authorization header is required",
				},
			})
			c.Abort()
			return
		}

		// Check Bearer token format
		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    errors.ErrUnauthorized,
					"message": "Invalid authorization format. Use 'Bearer <token>'",
				},
			})
			c.Abort()
			return
		}

		token := tokenParts[1]

		// Check if token is blacklisted (if session manager is available)
		// Note: This would require a proper interface type, but keeping it simple for now
		// TODO: Implement proper token blacklist checking with session manager

		// Validate token
		claims, err := tokenService.ValidateToken(token, auth.AccessToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error": gin.H{
					"code":    errors.ErrTokenInvalid,
					"message": "Invalid or expired token",
				},
			})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)

		c.Next()
	}
}

// RateLimit middleware for rate limiting using Redis
func RateLimit(rateLimiter ratelimit.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		ctx := c.Request.Context()

		// Check rate limit
		allowed, err := rateLimiter.Allow(ctx, clientIP)
		if err != nil {
			// Log error but allow request to continue
			c.Next()
			return
		}

		if !allowed {
			// Get usage information for headers
			usage, _ := rateLimiter.GetUsage(ctx, clientIP)
			if usage != nil {
				c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", usage.Limit))
				c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", usage.Remaining))
				c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", usage.ResetTime.Unix()))
			}

			c.JSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error": gin.H{
					"code":    errors.ErrRateLimit,
					"message": "Rate limit exceeded. Please try again later.",
				},
			})
			c.Abort()
			return
		}

		// Add rate limit headers
		usage, _ := rateLimiter.GetUsage(ctx, clientIP)
		if usage != nil {
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", usage.Limit))
			c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", usage.Remaining))
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", usage.ResetTime.Unix()))
		}

		c.Next()
	}
}

// RequestID middleware adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Generate a simple request ID (in production, use UUID)
			requestID = generateRequestID()
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)

		c.Next()
	}
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	// Simple timestamp-based ID (in production, use proper UUID)
	return string(rune(time.Now().UnixNano()))
}

// Timeout middleware adds request timeout
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Add timeout to context
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// IPWhitelist middleware restricts access to allowed IP addresses
func IPWhitelist(allowedIPs []string, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// If no IPs are configured, allow all traffic
		if len(allowedIPs) == 0 {
			c.Next()
			return
		}

		clientIP := getClientIP(c)

		// Check if client IP is in the allowed list
		allowed := false
		for _, allowedIP := range allowedIPs {
			if isIPAllowed(clientIP, allowedIP) {
				allowed = true
				break
			}
		}

		if !allowed {
			log.Warn("IP access denied",
				"client_ip", clientIP,
				"allowed_ips", strings.Join(allowedIPs, ", "),
				"method", c.Request.Method,
				"path", c.Request.URL.Path,
			)

			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "IP_BLOCKED",
					"message": "Access denied: Your IP address is not allowed",
				},
			})
			c.Abort()
			return
		}

		// Log successful IP access for security monitoring
		log.Debug("IP access granted",
			"client_ip", clientIP,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
		)

		c.Next()
	}
}

// getClientIP extracts the real client IP considering proxies and load balancers
func getClientIP(c *gin.Context) string {
	// Priority order for IP detection:
	// 1. X-Real-IP header (nginx proxy)
	// 2. X-Forwarded-For header (load balancers, proxies)
	// 3. RemoteAddr (direct connection)

	// Check X-Real-IP header first
	if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Check X-Forwarded-For header
	if forwardedFor := c.GetHeader("X-Forwarded-For"); forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
		// The first IP is usually the original client
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Fallback to RemoteAddr
	remoteAddr := c.Request.RemoteAddr

	// Try to split host and port
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If SplitHostPort fails, RemoteAddr might not have a port
		// or it might be an IPv6 address without proper brackets
		// Just return the RemoteAddr as-is and let IP parsing handle it later
		return remoteAddr
	}
	return ip
}

// isIPAllowed checks if a client IP is allowed by comparing against an allowed IP/CIDR
func isIPAllowed(clientIP, allowedIP string) bool {
	// Direct IP match
	if clientIP == allowedIP {
		return true
	}

	// Check if allowedIP is a CIDR range
	if strings.Contains(allowedIP, "/") {
		_, cidr, err := net.ParseCIDR(allowedIP)
		if err != nil {
			return false
		}

		ip := net.ParseIP(clientIP)
		if ip == nil {
			return false
		}

		return cidr.Contains(ip)
	}

	// If allowedIP is just an IP without CIDR, parse and compare
	allowedIPParsed := net.ParseIP(allowedIP)
	clientIPParsed := net.ParseIP(clientIP)

	if allowedIPParsed == nil || clientIPParsed == nil {
		return false
	}

	return allowedIPParsed.Equal(clientIPParsed)
}
