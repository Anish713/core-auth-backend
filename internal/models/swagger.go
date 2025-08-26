package models

import "time"

// APIResponse represents a standard API response structure
type APIResponse struct {
	Success bool        `json:"success" example:"true"`
	Message string      `json:"message,omitempty" example:"Operation successful"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// APIError represents an error response structure
type APIError struct {
	Code    string `json:"code" example:"validation_error"`
	Message string `json:"message" example:"Invalid input provided"`
	Details string `json:"details,omitempty" example:"Email format is invalid"`
}

// AuthSuccessResponse represents a successful authentication response
type AuthSuccessResponse struct {
	Success bool         `json:"success" example:"true"`
	Message string       `json:"message" example:"Sign in successful"`
	Data    AuthResponse `json:"data"`
}

// ProfileSuccessResponse represents a successful profile response
type ProfileSuccessResponse struct {
	Success bool        `json:"success" example:"true"`
	Data    UserProfile `json:"data"`
}

// SessionsSuccessResponse represents a successful sessions response
type SessionsSuccessResponse struct {
	Success bool         `json:"success" example:"true"`
	Data    SessionsData `json:"data"`
}

// SessionsData represents session data structure
type SessionsData struct {
	Sessions []SessionInfo `json:"sessions"`
}

// SessionInfo represents session information
type SessionInfo struct {
	ID        string    `json:"id" example:"session_123"`
	UserID    int64     `json:"user_id" example:"1"`
	IPAddress string    `json:"ip_address" example:"192.168.1.1"`
	UserAgent string    `json:"user_agent" example:"Mozilla/5.0..."`
	CreatedAt time.Time `json:"created_at" example:"2024-01-15T10:30:00Z"`
	LastSeen  time.Time `json:"last_seen" example:"2024-01-15T14:30:00Z"`
	IsCurrent bool      `json:"is_current" example:"true"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string `json:"status" example:"ok"`
	Timestamp string `json:"timestamp" example:"2024-01-15T10:30:00Z"`
	Uptime    string `json:"uptime" example:"1h23m45s"`
}

// ReadinessResponse represents readiness check response
type ReadinessResponse struct {
	Status    string                 `json:"status" example:"ok"`
	Timestamp string                 `json:"timestamp" example:"2024-01-15T10:30:00Z"`
	Uptime    string                 `json:"uptime" example:"1h23m45s"`
	Checks    map[string]interface{} `json:"checks"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Success bool     `json:"success" example:"false"`
	Error   APIError `json:"error"`
}

// SuccessResponse represents a simple success response
type SuccessResponse struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message" example:"Operation completed successfully"`
}
