package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"auth-service/pkg/cache"
)

// SessionManager defines the interface for session management
type SessionManager interface {
	// Session lifecycle
	CreateSession(ctx context.Context, userID int64, email string, metadata map[string]interface{}) (*Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	RefreshSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error

	// User session management
	GetUserSessions(ctx context.Context, userID int64) ([]*Session, error)
	DeleteUserSessions(ctx context.Context, userID int64) error
	DeleteAllUserSessionsExcept(ctx context.Context, userID int64, keepSessionID string) error

	// Token management
	BlacklistToken(ctx context.Context, tokenID string, expiresAt time.Time) error
	IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error)
	CleanupExpiredTokens(ctx context.Context) error

	// Session validation
	ValidateSession(ctx context.Context, sessionID string) (*Session, error)
	ExtendSession(ctx context.Context, sessionID string, extension time.Duration) error

	// Session monitoring
	GetActiveSessionsCount(ctx context.Context) (int64, error)
	GetUserActiveSessionsCount(ctx context.Context, userID int64) (int64, error)
	GetSessionActivity(ctx context.Context, sessionID string) (*SessionActivity, error)

	// Session cleanup
	CleanupExpiredSessions(ctx context.Context) error
}

// Session represents a user session
type Session struct {
	ID         string                 `json:"id"`
	UserID     int64                  `json:"user_id"`
	Email      string                 `json:"email"`
	CreatedAt  time.Time              `json:"created_at"`
	LastAccess time.Time              `json:"last_access"`
	ExpiresAt  time.Time              `json:"expires_at"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	DeviceInfo string                 `json:"device_info,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	IsActive   bool                   `json:"is_active"`
}

// SessionActivity represents session activity metrics
type SessionActivity struct {
	SessionID       string        `json:"session_id"`
	RequestCount    int64         `json:"request_count"`
	LastRequestTime time.Time     `json:"last_request_time"`
	Duration        time.Duration `json:"duration"`
	IPAddresses     []string      `json:"ip_addresses"`
}

// sessionManager implements SessionManager using Redis
type sessionManager struct {
	sessionService cache.SessionService
	cache          cache.CacheService
	defaultTTL     time.Duration
	maxSessions    int // Maximum sessions per user
}

// SessionManagerConfig configuration for session manager
type SessionManagerConfig struct {
	DefaultTTL     time.Duration
	MaxSessions    int
	CleanupEnabled bool
}

// NewSessionManager creates a new session manager
func NewSessionManager(sessionService cache.SessionService, cacheService cache.CacheService, config *SessionManagerConfig) SessionManager {
	if config == nil {
		config = &SessionManagerConfig{
			DefaultTTL:  24 * time.Hour,
			MaxSessions: 5,
		}
	}

	return &sessionManager{
		sessionService: sessionService,
		cache:          cacheService,
		defaultTTL:     config.DefaultTTL,
		maxSessions:    config.MaxSessions,
	}
}

// CreateSession creates a new session for a user
func (sm *sessionManager) CreateSession(ctx context.Context, userID int64, email string, metadata map[string]interface{}) (*Session, error) {
	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Check user session limit
	existingSessions, err := sm.GetUserSessions(ctx, userID)
	if err != nil && !cache.IsNotFoundError(err) {
		return nil, fmt.Errorf("failed to get existing sessions: %w", err)
	}

	// Remove oldest session if limit exceeded
	if len(existingSessions) >= sm.maxSessions {
		// Sort by creation time and remove oldest
		oldestSession := existingSessions[0]
		for _, session := range existingSessions {
			if session.CreatedAt.Before(oldestSession.CreatedAt) {
				oldestSession = session
			}
		}

		if err := sm.DeleteSession(ctx, oldestSession.ID); err != nil {
			// Log but don't fail the operation
		}
	}

	// Create session
	now := time.Now()
	session := &Session{
		ID:         sessionID,
		UserID:     userID,
		Email:      email,
		CreatedAt:  now,
		LastAccess: now,
		ExpiresAt:  now.Add(sm.defaultTTL),
		Metadata:   metadata,
		IsActive:   true,
	}

	// Store session data
	sessionData := &cache.SessionData{
		UserID:    userID,
		Email:     email,
		IssuedAt:  now,
		ExpiresAt: session.ExpiresAt,
		Metadata:  metadata,
	}

	if err := sm.sessionService.SetSession(ctx, sessionID, sessionData, sm.defaultTTL); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Update user sessions list
	userSessions := make([]string, 0, len(existingSessions)+1)
	for _, s := range existingSessions {
		if s.ID != sessionID { // Avoid duplicates
			userSessions = append(userSessions, s.ID)
		}
	}
	userSessions = append(userSessions, sessionID)

	if err := sm.sessionService.SetUserSessions(ctx, userID, userSessions); err != nil {
		// Log error but don't fail
	}

	// Initialize session activity
	activity := &SessionActivity{
		SessionID:       sessionID,
		RequestCount:    1,
		LastRequestTime: now,
		Duration:        0,
		IPAddresses:     []string{},
	}

	activityKey := fmt.Sprintf("activity:%s", sessionID)
	if err := sm.cache.Set(ctx, activityKey, activity, sm.defaultTTL); err != nil {
		// Log error but don't fail
	}

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *sessionManager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	sessionData, err := sm.sessionService.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:         sessionID,
		UserID:     sessionData.UserID,
		Email:      sessionData.Email,
		CreatedAt:  sessionData.IssuedAt,
		LastAccess: sessionData.IssuedAt, // Will be updated with activity
		ExpiresAt:  sessionData.ExpiresAt,
		Metadata:   sessionData.Metadata,
		IsActive:   time.Now().Before(sessionData.ExpiresAt),
	}

	// Get activity data
	activity, err := sm.GetSessionActivity(ctx, sessionID)
	if err == nil {
		session.LastAccess = activity.LastRequestTime
	}

	return session, nil
}

// RefreshSession extends a session's expiration time
func (sm *sessionManager) RefreshSession(ctx context.Context, sessionID string) (*Session, error) {
	session, err := sm.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if !session.IsActive {
		return nil, fmt.Errorf("session is not active")
	}

	// Extend expiration
	newExpiration := time.Now().Add(sm.defaultTTL)
	if err := sm.sessionService.RefreshSession(ctx, sessionID, sm.defaultTTL); err != nil {
		return nil, fmt.Errorf("failed to refresh session: %w", err)
	}

	session.ExpiresAt = newExpiration
	session.LastAccess = time.Now()

	// Update activity
	sm.updateSessionActivity(ctx, sessionID, session.IPAddress)

	return session, nil
}

// DeleteSession removes a session
func (sm *sessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	// Get session to find user
	session, err := sm.GetSession(ctx, sessionID)
	if err != nil && !cache.IsNotFoundError(err) {
		return err
	}

	// Delete session data
	if err := sm.sessionService.DeleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Update user sessions list if we found the session
	if session != nil {
		userSessions, err := sm.sessionService.GetUserSessions(ctx, session.UserID)
		if err == nil {
			updatedSessions := make([]string, 0, len(userSessions))
			for _, id := range userSessions {
				if id != sessionID {
					updatedSessions = append(updatedSessions, id)
				}
			}
			sm.sessionService.SetUserSessions(ctx, session.UserID, updatedSessions)
		}
	}

	// Delete activity data
	activityKey := fmt.Sprintf("activity:%s", sessionID)
	sm.cache.Delete(ctx, activityKey)

	return nil
}

// GetUserSessions retrieves all sessions for a user
func (sm *sessionManager) GetUserSessions(ctx context.Context, userID int64) ([]*Session, error) {
	sessionIDs, err := sm.sessionService.GetUserSessions(ctx, userID)
	if err != nil {
		if cache.IsNotFoundError(err) {
			return []*Session{}, nil
		}
		return nil, err
	}

	sessions := make([]*Session, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		session, err := sm.GetSession(ctx, sessionID)
		if err != nil {
			// Session might have expired, skip it
			continue
		}

		if session.IsActive {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// DeleteUserSessions removes all sessions for a user
func (sm *sessionManager) DeleteUserSessions(ctx context.Context, userID int64) error {
	return sm.sessionService.DeleteUserSessions(ctx, userID)
}

// DeleteAllUserSessionsExcept removes all user sessions except the specified one
func (sm *sessionManager) DeleteAllUserSessionsExcept(ctx context.Context, userID int64, keepSessionID string) error {
	sessions, err := sm.GetUserSessions(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.ID != keepSessionID {
			if err := sm.DeleteSession(ctx, session.ID); err != nil {
				// Log error but continue
				continue
			}
		}
	}

	return nil
}

// BlacklistToken adds a token to the blacklist
func (sm *sessionManager) BlacklistToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	expiration := time.Until(expiresAt)
	if expiration <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	return sm.sessionService.BlacklistToken(ctx, tokenID, expiration)
}

// IsTokenBlacklisted checks if a token is blacklisted
func (sm *sessionManager) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	return sm.sessionService.IsTokenBlacklisted(ctx, tokenID)
}

// CleanupExpiredTokens removes expired tokens from blacklist
func (sm *sessionManager) CleanupExpiredTokens(ctx context.Context) error {
	// Redis TTL handles this automatically
	return nil
}

// ValidateSession validates and updates session activity
func (sm *sessionManager) ValidateSession(ctx context.Context, sessionID string) (*Session, error) {
	session, err := sm.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if !session.IsActive {
		return nil, fmt.Errorf("session is expired or inactive")
	}

	// Update last access
	sm.updateSessionActivity(ctx, sessionID, "")

	return session, nil
}

// ExtendSession extends a session's lifetime
func (sm *sessionManager) ExtendSession(ctx context.Context, sessionID string, extension time.Duration) error {
	return sm.sessionService.RefreshSession(ctx, sessionID, extension)
}

// GetActiveSessionsCount returns total active sessions
func (sm *sessionManager) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	return sm.sessionService.GetActiveSessionCount(ctx)
}

// GetUserActiveSessionsCount returns active sessions for a user
func (sm *sessionManager) GetUserActiveSessionsCount(ctx context.Context, userID int64) (int64, error) {
	sessions, err := sm.GetUserSessions(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int64(len(sessions)), nil
}

// GetSessionActivity retrieves session activity metrics
func (sm *sessionManager) GetSessionActivity(ctx context.Context, sessionID string) (*SessionActivity, error) {
	activityKey := fmt.Sprintf("activity:%s", sessionID)
	var activity SessionActivity

	err := sm.cache.Get(ctx, activityKey, &activity)
	if err != nil {
		if cache.IsNotFoundError(err) {
			// Return default activity
			return &SessionActivity{
				SessionID:       sessionID,
				RequestCount:    0,
				LastRequestTime: time.Now(),
				Duration:        0,
				IPAddresses:     []string{},
			}, nil
		}
		return nil, err
	}

	return &activity, nil
}

// CleanupExpiredSessions removes expired sessions
func (sm *sessionManager) CleanupExpiredSessions(ctx context.Context) error {
	// This would typically be handled by Redis TTL
	// For manual cleanup, we could iterate through session patterns
	return nil
}

// updateSessionActivity updates session activity metrics
func (sm *sessionManager) updateSessionActivity(ctx context.Context, sessionID, ipAddress string) {
	activityKey := fmt.Sprintf("activity:%s", sessionID)

	activity, err := sm.GetSessionActivity(ctx, sessionID)
	if err != nil {
		return // Log error
	}

	activity.RequestCount++
	activity.LastRequestTime = time.Now()

	if ipAddress != "" {
		// Add IP to list if not already present
		found := false
		for _, ip := range activity.IPAddresses {
			if ip == ipAddress {
				found = true
				break
			}
		}
		if !found {
			activity.IPAddresses = append(activity.IPAddresses, ipAddress)
		}
	}

	// Store updated activity
	sm.cache.Set(ctx, activityKey, activity, sm.defaultTTL)
}

// generateSessionID generates a cryptographically secure session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
