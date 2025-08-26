package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestIPWhitelist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.New()

	tests := []struct {
		name           string
		allowedIPs     []string
		clientIP       string
		headers        map[string]string
		expectedStatus int
		expectBlocked  bool
	}{
		{
			name:           "Empty whitelist allows all IPs",
			allowedIPs:     []string{},
			clientIP:       "192.168.1.100",
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
		{
			name:           "Exact IP match allowed",
			allowedIPs:     []string{"192.168.1.100", "10.0.0.1"},
			clientIP:       "192.168.1.100",
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
		{
			name:           "IP not in whitelist blocked",
			allowedIPs:     []string{"192.168.1.100", "10.0.0.1"},
			clientIP:       "203.0.113.5",
			expectedStatus: http.StatusForbidden,
			expectBlocked:  true,
		},
		{
			name:           "CIDR range allows IP",
			allowedIPs:     []string{"192.168.1.0/24", "10.0.0.0/8"},
			clientIP:       "192.168.1.150",
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
		{
			name:           "CIDR range blocks IP outside range",
			allowedIPs:     []string{"192.168.1.0/24", "10.0.0.0/8"},
			clientIP:       "192.168.2.1",
			expectedStatus: http.StatusForbidden,
			expectBlocked:  true,
		},
		{
			name:           "X-Real-IP header takes precedence",
			allowedIPs:     []string{"203.0.113.5"},
			clientIP:       "192.168.1.1", // This would normally be blocked
			headers:        map[string]string{"X-Real-IP": "203.0.113.5"},
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
		{
			name:           "X-Forwarded-For header used when X-Real-IP absent",
			allowedIPs:     []string{"203.0.113.10"},
			clientIP:       "192.168.1.1", // This would normally be blocked
			headers:        map[string]string{"X-Forwarded-For": "203.0.113.10, 192.168.1.1"},
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
		{
			name:           "IPv6 address exact match",
			allowedIPs:     []string{"::1", "2001:db8::1"},
			clientIP:       "::1",
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
		{
			name:           "IPv6 CIDR range",
			allowedIPs:     []string{"2001:db8::/32"},
			clientIP:       "2001:db8:0:0:0:0:0:1",
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
		{
			name:           "Mixed IPv4 and IPv6 whitelist",
			allowedIPs:     []string{"192.168.1.0/24", "::1", "2001:db8::/32"},
			clientIP:       "192.168.1.50",
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router with middleware
			router := gin.New()
			router.Use(IPWhitelist(tt.allowedIPs, log))

			// Add a test endpoint
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)

			// Format RemoteAddr properly for IPv6
			if strings.Contains(tt.clientIP, ":") && !strings.Contains(tt.clientIP, "[") {
				// IPv6 address - wrap in brackets when adding port
				req.RemoteAddr = "[" + tt.clientIP + "]:12345"
			} else {
				// IPv4 address or already properly formatted
				req.RemoteAddr = tt.clientIP + ":12345"
			}

			// Add custom headers if specified
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Perform request
			router.ServeHTTP(w, req)

			// Assert status code
			assert.Equal(t, tt.expectedStatus, w.Code, "Status code mismatch for test: %s", tt.name)

			// If blocked, check error response format
			if tt.expectBlocked {
				assert.Contains(t, w.Body.String(), "IP_BLOCKED", "Expected IP_BLOCKED error code")
				assert.Contains(t, w.Body.String(), "Access denied", "Expected access denied message")
			} else {
				assert.Contains(t, w.Body.String(), "success", "Expected success response")
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expectedIP string
	}{
		{
			name:       "X-Real-IP takes precedence",
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Real-IP": "203.0.113.5"},
			expectedIP: "203.0.113.5",
		},
		{
			name:       "X-Forwarded-For first IP when X-Real-IP absent",
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.10, 192.168.1.100, 10.0.0.1"},
			expectedIP: "203.0.113.10",
		},
		{
			name:       "RemoteAddr fallback when headers absent",
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{},
			expectedIP: "192.168.1.1",
		},
		{
			name:       "Handle RemoteAddr without port",
			remoteAddr: "192.168.1.1",
			headers:    map[string]string{},
			expectedIP: "192.168.1.1",
		},
		{
			name:       "X-Real-IP overrides X-Forwarded-For",
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Real-IP":       "203.0.113.5",
				"X-Forwarded-For": "203.0.113.10, 192.168.1.100",
			},
			expectedIP: "203.0.113.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Create gin context
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Test getClientIP function
			actualIP := getClientIP(c)
			assert.Equal(t, tt.expectedIP, actualIP, "Client IP extraction failed for test: %s", tt.name)
		})
	}
}

func TestIsIPAllowed(t *testing.T) {
	tests := []struct {
		name      string
		clientIP  string
		allowedIP string
		expected  bool
	}{
		{
			name:      "Exact IPv4 match",
			clientIP:  "192.168.1.1",
			allowedIP: "192.168.1.1",
			expected:  true,
		},
		{
			name:      "IPv4 no match",
			clientIP:  "192.168.1.1",
			allowedIP: "192.168.1.2",
			expected:  false,
		},
		{
			name:      "IPv4 CIDR match",
			clientIP:  "192.168.1.50",
			allowedIP: "192.168.1.0/24",
			expected:  true,
		},
		{
			name:      "IPv4 CIDR no match",
			clientIP:  "192.168.2.1",
			allowedIP: "192.168.1.0/24",
			expected:  false,
		},
		{
			name:      "IPv6 exact match",
			clientIP:  "::1",
			allowedIP: "::1",
			expected:  true,
		},
		{
			name:      "IPv6 CIDR match",
			clientIP:  "2001:db8:0:0:0:0:0:1",
			allowedIP: "2001:db8::/32",
			expected:  true,
		},
		{
			name:      "Invalid client IP",
			clientIP:  "invalid-ip",
			allowedIP: "192.168.1.0/24",
			expected:  false,
		},
		{
			name:      "Invalid CIDR",
			clientIP:  "192.168.1.1",
			allowedIP: "192.168.1.0/invalid",
			expected:  false,
		},
		{
			name:      "Localhost match",
			clientIP:  "127.0.0.1",
			allowedIP: "127.0.0.1",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPAllowed(tt.clientIP, tt.allowedIP)
			assert.Equal(t, tt.expected, result, "IP allowed check failed for test: %s", tt.name)
		})
	}
}

// Benchmark tests to ensure performance is acceptable
func BenchmarkIPWhitelist(b *testing.B) {
	gin.SetMode(gin.TestMode)
	log := logger.New()

	allowedIPs := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"203.0.113.5",
		"2001:db8::/32",
	}

	router := gin.New()
	router.Use(IPWhitelist(allowedIPs, log))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
