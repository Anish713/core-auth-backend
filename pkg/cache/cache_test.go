package cache

import (
	"context"
	"testing"
	"time"

	"auth-service/pkg/redis"
)

func TestSerializeValue(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "String value",
			input:    "test string",
			expected: "test string",
		},
		{
			name:     "Integer value",
			input:    42,
			expected: "42",
		},
		{
			name:     "Boolean value",
			input:    true,
			expected: "true",
		},
		{
			name:     "Struct value",
			input:    struct{ Name string }{Name: "test"},
			expected: `{"Name":"test"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SerializeValue(tt.input)
			if err != nil {
				t.Errorf("SerializeValue failed: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDeserializeValue(t *testing.T) {
	t.Run("String value", func(t *testing.T) {
		var result string
		err := DeserializeValue("test string", &result)
		if err != nil {
			t.Errorf("DeserializeValue failed: %v", err)
		}
		if result != "test string" {
			t.Errorf("Expected 'test string', got %s", result)
		}
	})

	t.Run("Integer value", func(t *testing.T) {
		var result int
		err := DeserializeValue("42", &result)
		if err != nil {
			t.Errorf("DeserializeValue failed: %v", err)
		}
		if result != 42 {
			t.Errorf("Expected 42, got %d", result)
		}
	})

	t.Run("Struct value", func(t *testing.T) {
		type TestStruct struct {
			Name string `json:"name"`
		}
		var result TestStruct
		err := DeserializeValue(`{"name":"test"}`, &result)
		if err != nil {
			t.Errorf("DeserializeValue failed: %v", err)
		}
		if result.Name != "test" {
			t.Errorf("Expected 'test', got %s", result.Name)
		}
	})
}

func TestKeyGenerators(t *testing.T) {
	tests := []struct {
		name     string
		function func() string
		expected string
	}{
		{
			name:     "SessionKey",
			function: func() string { return SessionKey("test123") },
			expected: "session:test123",
		},
		{
			name:     "UserSessionKey",
			function: func() string { return UserSessionKey(123) },
			expected: "user_sessions:123",
		},
		{
			name:     "BlacklistKey",
			function: func() string { return BlacklistKey("token123") },
			expected: "blacklist:token123",
		},
		{
			name:     "RateLimitKey",
			function: func() string { return RateLimitKey("192.168.1.1") },
			expected: "rate_limit:192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.function()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestCacheError(t *testing.T) {
	t.Run("Error with underlying error", func(t *testing.T) {
		originalErr := &CacheError{Type: ErrConnection, Message: "connection failed"}
		err := NewCacheError(ErrSerialization, "serialize failed", originalErr)

		expected := "SERIALIZATION_ERROR: serialize failed (CONNECTION_ERROR: connection failed)"
		if err.Error() != expected {
			t.Errorf("Expected %s, got %s", expected, err.Error())
		}

		if err.Unwrap() != originalErr {
			t.Error("Expected Unwrap to return original error")
		}
	})

	t.Run("Error without underlying error", func(t *testing.T) {
		err := NewCacheError(ErrNotFound, "key not found", nil)

		expected := "NOT_FOUND: key not found"
		if err.Error() != expected {
			t.Errorf("Expected %s, got %s", expected, err.Error())
		}

		if err.Unwrap() != nil {
			t.Error("Expected Unwrap to return nil")
		}
	})
}

func TestIsNotFoundError(t *testing.T) {
	t.Run("CacheError with NOT_FOUND type", func(t *testing.T) {
		err := NewCacheError(ErrNotFound, "key not found", nil)
		if !IsNotFoundError(err) {
			t.Error("Expected IsNotFoundError to return true")
		}
	})

	t.Run("CacheError with different type", func(t *testing.T) {
		err := NewCacheError(ErrConnection, "connection failed", nil)
		if IsNotFoundError(err) {
			t.Error("Expected IsNotFoundError to return false")
		}
	})

	t.Run("Non-CacheError", func(t *testing.T) {
		err := &CacheError{Type: ErrNotFound}
		if !IsNotFoundError(err) {
			t.Error("Expected IsNotFoundError to return true")
		}
	})
}

// Integration tests for Redis cache service
func TestRedisCacheIntegration(t *testing.T) {
	// Setup Redis client
	config := redis.DefaultConfig()
	client, err := redis.NewClient(config)
	if err != nil {
		t.Skipf("Redis not available for integration test: %v", err)
	}
	defer client.Close()

	cache := NewRedisCache(client)
	ctx := context.Background()

	t.Run("SetAndGet", func(t *testing.T) {
		key := "test:set_get"
		value := "test_value"

		err := cache.Set(ctx, key, value, time.Minute)
		if err != nil {
			t.Errorf("Set failed: %v", err)
		}

		var result string
		err = cache.Get(ctx, key, &result)
		if err != nil {
			t.Errorf("Get failed: %v", err)
		}

		if result != value {
			t.Errorf("Expected %s, got %s", value, result)
		}

		// Cleanup
		cache.Delete(ctx, key)
	})

	t.Run("GetNonExistentKey", func(t *testing.T) {
		var result string
		err := cache.Get(ctx, "non_existent_key", &result)
		if !IsNotFoundError(err) {
			t.Errorf("Expected not found error, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		key := "test:delete"
		value := "test_value"

		// Set value
		cache.Set(ctx, key, value, time.Minute)

		// Delete value
		err := cache.Delete(ctx, key)
		if err != nil {
			t.Errorf("Delete failed: %v", err)
		}

		// Verify deletion
		var result string
		err = cache.Get(ctx, key, &result)
		if !IsNotFoundError(err) {
			t.Error("Expected key to be deleted")
		}
	})

	t.Run("Exists", func(t *testing.T) {
		key := "test:exists"
		value := "test_value"

		// Check non-existent key
		exists, err := cache.Exists(ctx, key)
		if err != nil {
			t.Errorf("Exists failed: %v", err)
		}
		if exists {
			t.Error("Expected key to not exist")
		}

		// Set value
		cache.Set(ctx, key, value, time.Minute)

		// Check existing key
		exists, err = cache.Exists(ctx, key)
		if err != nil {
			t.Errorf("Exists failed: %v", err)
		}
		if !exists {
			t.Error("Expected key to exist")
		}

		// Cleanup
		cache.Delete(ctx, key)
	})

	t.Run("SetMultiple", func(t *testing.T) {
		items := map[string]interface{}{
			"test:multi1": "value1",
			"test:multi2": "value2",
			"test:multi3": 123,
		}

		err := cache.SetMultiple(ctx, items, time.Minute)
		if err != nil {
			t.Errorf("SetMultiple failed: %v", err)
		}

		// Verify values
		var result1 string
		cache.Get(ctx, "test:multi1", &result1)
		if result1 != "value1" {
			t.Errorf("Expected value1, got %s", result1)
		}

		var result3 int
		cache.Get(ctx, "test:multi3", &result3)
		if result3 != 123 {
			t.Errorf("Expected 123, got %d", result3)
		}

		// Cleanup
		for key := range items {
			cache.Delete(ctx, key)
		}
	})

	t.Run("GetMultiple", func(t *testing.T) {
		// Set test values
		cache.Set(ctx, "test:get_multi1", "value1", time.Minute)
		cache.Set(ctx, "test:get_multi2", "value2", time.Minute)

		keys := []string{"test:get_multi1", "test:get_multi2", "test:non_existent"}
		results, err := cache.GetMultiple(ctx, keys)
		if err != nil {
			t.Errorf("GetMultiple failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 results, got %d", len(results))
		}

		if results["test:get_multi1"] != "value1" {
			t.Errorf("Expected value1, got %v", results["test:get_multi1"])
		}

		// Cleanup
		cache.Delete(ctx, "test:get_multi1")
		cache.Delete(ctx, "test:get_multi2")
	})

	t.Run("IncrementOperations", func(t *testing.T) {
		key := "test:counter"

		// Test increment
		result, err := cache.Increment(ctx, key)
		if err != nil {
			t.Errorf("Increment failed: %v", err)
		}
		if result != 1 {
			t.Errorf("Expected 1, got %d", result)
		}

		// Test increment by value
		result, err = cache.IncrementBy(ctx, key, 5)
		if err != nil {
			t.Errorf("IncrementBy failed: %v", err)
		}
		if result != 6 {
			t.Errorf("Expected 6, got %d", result)
		}

		// Test decrement
		result, err = cache.Decrement(ctx, key)
		if err != nil {
			t.Errorf("Decrement failed: %v", err)
		}
		if result != 5 {
			t.Errorf("Expected 5, got %d", result)
		}

		// Test decrement by value
		result, err = cache.DecrementBy(ctx, key, 3)
		if err != nil {
			t.Errorf("DecrementBy failed: %v", err)
		}
		if result != 2 {
			t.Errorf("Expected 2, got %d", result)
		}

		// Cleanup
		cache.Delete(ctx, key)
	})

	t.Run("TTLOperations", func(t *testing.T) {
		key := "test:ttl"
		value := "test_value"

		// Set value with TTL
		cache.Set(ctx, key, value, time.Minute)

		// Get TTL
		ttl, err := cache.GetTTL(ctx, key)
		if err != nil {
			t.Errorf("GetTTL failed: %v", err)
		}
		if ttl <= 0 || ttl > time.Minute {
			t.Errorf("Expected TTL between 0 and 1 minute, got %v", ttl)
		}

		// Set new TTL
		err = cache.SetTTL(ctx, key, 30*time.Second)
		if err != nil {
			t.Errorf("SetTTL failed: %v", err)
		}

		// Verify new TTL
		ttl, err = cache.GetTTL(ctx, key)
		if err != nil {
			t.Errorf("GetTTL failed: %v", err)
		}
		if ttl > 30*time.Second {
			t.Errorf("Expected TTL <= 30 seconds, got %v", ttl)
		}

		// Cleanup
		cache.Delete(ctx, key)
	})

	t.Run("HealthCheck", func(t *testing.T) {
		err := cache.HealthCheck(ctx)
		if err != nil {
			t.Errorf("HealthCheck failed: %v", err)
		}
	})
}

func TestRedisSessionServiceIntegration(t *testing.T) {
	// Setup Redis client
	config := redis.DefaultConfig()
	client, err := redis.NewClient(config)
	if err != nil {
		t.Skipf("Redis not available for integration test: %v", err)
	}
	defer client.Close()

	sessionService := NewRedisSessionService(client)
	ctx := context.Background()

	t.Run("SessionOperations", func(t *testing.T) {
		sessionID := "test_session_123"
		data := &SessionData{
			UserID:    123,
			Email:     "test@example.com",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
			Metadata:  map[string]interface{}{"role": "user"},
		}

		// Set session
		err := sessionService.SetSession(ctx, sessionID, data, time.Hour)
		if err != nil {
			t.Errorf("SetSession failed: %v", err)
		}

		// Get session
		retrieved, err := sessionService.GetSession(ctx, sessionID)
		if err != nil {
			t.Errorf("GetSession failed: %v", err)
		}

		if retrieved.UserID != data.UserID {
			t.Errorf("Expected UserID %d, got %d", data.UserID, retrieved.UserID)
		}

		if retrieved.Email != data.Email {
			t.Errorf("Expected Email %s, got %s", data.Email, retrieved.Email)
		}

		// Refresh session
		err = sessionService.RefreshSession(ctx, sessionID, 2*time.Hour)
		if err != nil {
			t.Errorf("RefreshSession failed: %v", err)
		}

		// Delete session
		err = sessionService.DeleteSession(ctx, sessionID)
		if err != nil {
			t.Errorf("DeleteSession failed: %v", err)
		}

		// Verify deletion
		_, err = sessionService.GetSession(ctx, sessionID)
		if !IsNotFoundError(err) {
			t.Error("Expected session to be deleted")
		}
	})

	t.Run("UserSessionOperations", func(t *testing.T) {
		userID := int64(456)
		sessionIDs := []string{"session1", "session2", "session3"}

		// Set user sessions
		err := sessionService.SetUserSessions(ctx, userID, sessionIDs)
		if err != nil {
			t.Errorf("SetUserSessions failed: %v", err)
		}

		// Get user sessions
		retrieved, err := sessionService.GetUserSessions(ctx, userID)
		if err != nil {
			t.Errorf("GetUserSessions failed: %v", err)
		}

		if len(retrieved) != len(sessionIDs) {
			t.Errorf("Expected %d sessions, got %d", len(sessionIDs), len(retrieved))
		}

		// Verify session IDs
		for i, sessionID := range sessionIDs {
			if retrieved[i] != sessionID {
				t.Errorf("Expected session %s, got %s", sessionID, retrieved[i])
			}
		}

		// Delete user sessions
		err = sessionService.DeleteUserSessions(ctx, userID)
		if err != nil {
			t.Errorf("DeleteUserSessions failed: %v", err)
		}

		// Verify deletion
		retrieved, err = sessionService.GetUserSessions(ctx, userID)
		if err != nil {
			t.Errorf("GetUserSessions failed: %v", err)
		}
		if len(retrieved) != 0 {
			t.Error("Expected no user sessions after deletion")
		}
	})

	t.Run("TokenBlacklist", func(t *testing.T) {
		tokenID := "test_token_123"

		// Check if token is blacklisted (should be false)
		blacklisted, err := sessionService.IsTokenBlacklisted(ctx, tokenID)
		if err != nil {
			t.Errorf("IsTokenBlacklisted failed: %v", err)
		}
		if blacklisted {
			t.Error("Expected token to not be blacklisted")
		}

		// Blacklist token
		err = sessionService.BlacklistToken(ctx, tokenID, time.Minute)
		if err != nil {
			t.Errorf("BlacklistToken failed: %v", err)
		}

		// Check if token is blacklisted (should be true)
		blacklisted, err = sessionService.IsTokenBlacklisted(ctx, tokenID)
		if err != nil {
			t.Errorf("IsTokenBlacklisted failed: %v", err)
		}
		if !blacklisted {
			t.Error("Expected token to be blacklisted")
		}
	})

	t.Run("SessionCounts", func(t *testing.T) {
		// This test assumes no other active sessions
		count, err := sessionService.GetActiveSessionCount(ctx)
		if err != nil {
			t.Errorf("GetActiveSessionCount failed: %v", err)
		}
		if count < 0 {
			t.Error("Expected non-negative session count")
		}

		userID := int64(789)
		count, err = sessionService.GetUserSessionCount(ctx, userID)
		if err != nil {
			t.Errorf("GetUserSessionCount failed: %v", err)
		}
		if count != 0 {
			t.Errorf("Expected 0 user sessions, got %d", count)
		}
	})
}
