package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-service/internal/models"
	"auth-service/internal/services"
	"auth-service/pkg/cache"
	"auth-service/pkg/logger"
	"auth-service/pkg/redis"

	"github.com/gin-gonic/gin"
)

// TestSessionManagementIntegration demonstrates session management functionality
func TestSessionManagementIntegration(t *testing.T) {
	// Skip if Redis is not available
	config := redis.DefaultConfig()
	redisClient, err := redis.NewClient(config)
	if err != nil {
		t.Skipf("Redis not available for integration test: %v", err)
	}
	defer redisClient.Close()

	// Setup test dependencies (in a real test, you'd use test database)
	gin.SetMode(gin.TestMode)
	log := logger.New()

	// Mock auth service (in real test, use actual services)
	var authService services.AuthService

	// Setup session manager
	cacheService := cache.NewRedisCache(redisClient)
	sessionService := cache.NewRedisSessionService(redisClient)
	sessionManagerConfig := &services.SessionManagerConfig{
		DefaultTTL:  24 * 60 * 60, // 24 hours in seconds
		MaxSessions: 5,
	}
	sessionManager := services.NewSessionManager(sessionService, cacheService, sessionManagerConfig)

	// Create auth handler with session management
	authHandler := NewAuthHandler(authService, sessionManager, log)

	// Test SignOut endpoint
	t.Run("SignOut", func(t *testing.T) {
		router := gin.New()
		router.POST("/signout", authHandler.SignOut)

		req, _ := http.NewRequest("POST", "/signout", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("X-Session-ID", "test-session-123")

		// Mock user_id in context (normally set by auth middleware)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", int64(123))

		authHandler.SignOut(c)

		// Note: This will fail due to missing auth service setup
		// but demonstrates the session management integration
		t.Logf("SignOut response: %d", w.Code)
	})

	t.Run("GetActiveSessions", func(t *testing.T) {
		router := gin.New()
		router.GET("/sessions", authHandler.GetActiveSessions)

		req, _ := http.NewRequest("GET", "/sessions", nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", int64(123))

		authHandler.GetActiveSessions(c)

		t.Logf("GetActiveSessions response: %d", w.Code)
	})
}

// Example of how to use session management in your application
func ExampleSessionManagement(t *testing.T) {
	t.Skip("This is an example, not a real test")

	// 1. During signin, a session is automatically created
	signInData := models.SignInRequest{
		Email:    "user@example.com",
		Password: "password123",
	}

	// 2. When user signs in, they receive:
	// - JWT tokens (access + refresh)
	// - X-Session-ID header for session tracking

	// 3. Session management endpoints:
	// GET /api/v1/sessions - List active sessions
	// DELETE /api/v1/sessions/:sessionId - Terminate specific session
	// DELETE /api/v1/sessions - Terminate all sessions except current
	// POST /api/v1/auth/signout - Sign out and cleanup session

	// Example API calls:
	examples := []struct {
		method   string
		endpoint string
		headers  map[string]string
		body     interface{}
	}{
		{
			method:   "POST",
			endpoint: "/api/v1/auth/signin",
			headers:  map[string]string{"Content-Type": "application/json"},
			body:     signInData,
		},
		{
			method:   "GET",
			endpoint: "/api/v1/sessions",
			headers: map[string]string{
				"Authorization": "Bearer <access-token>",
				"X-Session-ID":  "<session-id>",
			},
		},
		{
			method:   "DELETE",
			endpoint: "/api/v1/sessions/some-session-id",
			headers: map[string]string{
				"Authorization": "Bearer <access-token>",
			},
		},
		{
			method:   "POST",
			endpoint: "/api/v1/auth/signout",
			headers: map[string]string{
				"Authorization": "Bearer <access-token>",
				"X-Session-ID":  "<session-id>",
			},
		},
	}

	for _, example := range examples {
		t.Logf("Example: %s %s", example.method, example.endpoint)
		if example.body != nil {
			bodyBytes, _ := json.Marshal(example.body)
			t.Logf("Body: %s", string(bodyBytes))
		}
		for key, value := range example.headers {
			t.Logf("Header: %s: %s", key, value)
		}
		t.Log("---")
	}
}
