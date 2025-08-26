package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// CacheService defines the interface for cache operations
type CacheService interface {
	// Basic cache operations
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string, dest interface{}) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)

	// Multi-key operations
	SetMultiple(ctx context.Context, items map[string]interface{}, expiration time.Duration) error
	GetMultiple(ctx context.Context, keys []string) (map[string]interface{}, error)
	DeleteMultiple(ctx context.Context, keys []string) error

	// TTL operations
	SetTTL(ctx context.Context, key string, expiration time.Duration) error
	GetTTL(ctx context.Context, key string) (time.Duration, error)

	// Pattern operations
	DeleteByPattern(ctx context.Context, pattern string) error
	GetKeysByPattern(ctx context.Context, pattern string) ([]string, error)

	// Counter operations
	Increment(ctx context.Context, key string) (int64, error)
	IncrementBy(ctx context.Context, key string, value int64) (int64, error)
	Decrement(ctx context.Context, key string) (int64, error)
	DecrementBy(ctx context.Context, key string, value int64) (int64, error)

	// Health check
	HealthCheck(ctx context.Context) error
}

// SessionData represents cached session information
type SessionData struct {
	UserID    int64                  `json:"user_id"`
	Email     string                 `json:"email"`
	IssuedAt  time.Time              `json:"issued_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// SessionService defines session-specific cache operations
type SessionService interface {
	// Session management
	SetSession(ctx context.Context, sessionID string, data *SessionData, expiration time.Duration) error
	GetSession(ctx context.Context, sessionID string) (*SessionData, error)
	DeleteSession(ctx context.Context, sessionID string) error
	RefreshSession(ctx context.Context, sessionID string, expiration time.Duration) error

	// User session management
	SetUserSessions(ctx context.Context, userID int64, sessionIDs []string) error
	GetUserSessions(ctx context.Context, userID int64) ([]string, error)
	DeleteUserSessions(ctx context.Context, userID int64) error

	// Token blacklisting
	BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error
	IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error)

	// Session statistics
	GetActiveSessionCount(ctx context.Context) (int64, error)
	GetUserSessionCount(ctx context.Context, userID int64) (int64, error)
}

// ErrorType represents cache error types
type ErrorType string

const (
	ErrNotFound      ErrorType = "NOT_FOUND"
	ErrSerialization ErrorType = "SERIALIZATION_ERROR"
	ErrConnection    ErrorType = "CONNECTION_ERROR"
	ErrInvalidKey    ErrorType = "INVALID_KEY"
)

// CacheError represents a cache-related error
type CacheError struct {
	Type    ErrorType
	Message string
	Err     error
}

func (e *CacheError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *CacheError) Unwrap() error {
	return e.Err
}

// NewCacheError creates a new cache error
func NewCacheError(errType ErrorType, message string, err error) *CacheError {
	return &CacheError{
		Type:    errType,
		Message: message,
		Err:     err,
	}
}

// IsNotFoundError checks if the error is a not found error
func IsNotFoundError(err error) bool {
	if cacheErr, ok := err.(*CacheError); ok {
		return cacheErr.Type == ErrNotFound
	}
	return false
}

// Common cache key patterns
const (
	SessionKeyPrefix     = "session:"
	UserSessionKeyPrefix = "user_sessions:"
	BlacklistKeyPrefix   = "blacklist:"
	RateLimitKeyPrefix   = "rate_limit:"
	SessionCountKey      = "session_count"
)

// Helper functions for key generation
func SessionKey(sessionID string) string {
	return SessionKeyPrefix + sessionID
}

func UserSessionKey(userID int64) string {
	return fmt.Sprintf("%s%d", UserSessionKeyPrefix, userID)
}

func BlacklistKey(tokenID string) string {
	return BlacklistKeyPrefix + tokenID
}

func RateLimitKey(identifier string) string {
	return RateLimitKeyPrefix + identifier
}

// SerializeValue serializes a value to JSON string
func SerializeValue(value interface{}) (string, error) {
	if str, ok := value.(string); ok {
		return str, nil
	}

	data, err := json.Marshal(value)
	if err != nil {
		return "", NewCacheError(ErrSerialization, "failed to serialize value", err)
	}
	return string(data), nil
}

// DeserializeValue deserializes a JSON string to the given destination
func DeserializeValue(data string, dest interface{}) error {
	if destStr, ok := dest.(*string); ok {
		*destStr = data
		return nil
	}

	if err := json.Unmarshal([]byte(data), dest); err != nil {
		return NewCacheError(ErrSerialization, "failed to deserialize value", err)
	}
	return nil
}
