package cache

import (
	"context"
	"time"

	redisClient "auth-service/pkg/redis"

	"github.com/redis/go-redis/v9"
)

// redisCache implements CacheService using Redis
type redisCache struct {
	client *redisClient.Client
}

// NewRedisCache creates a new Redis cache service
func NewRedisCache(client *redisClient.Client) CacheService {
	return &redisCache{
		client: client,
	}
}

// Set stores a value in Redis with expiration
func (r *redisCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	serialized, err := SerializeValue(value)
	if err != nil {
		return err
	}

	if err := r.client.Set(ctx, key, serialized, expiration).Err(); err != nil {
		return NewCacheError(ErrConnection, "failed to set value", err)
	}

	return nil
}

// Get retrieves a value from Redis
func (r *redisCache) Get(ctx context.Context, key string, dest interface{}) error {
	result, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return NewCacheError(ErrNotFound, "key not found", nil)
		}
		return NewCacheError(ErrConnection, "failed to get value", err)
	}

	return DeserializeValue(result, dest)
}

// Delete removes a key from Redis
func (r *redisCache) Delete(ctx context.Context, key string) error {
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return NewCacheError(ErrConnection, "failed to delete key", err)
	}
	return nil
}

// Exists checks if a key exists in Redis
func (r *redisCache) Exists(ctx context.Context, key string) (bool, error) {
	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, NewCacheError(ErrConnection, "failed to check key existence", err)
	}
	return result > 0, nil
}

// SetMultiple stores multiple key-value pairs with expiration
func (r *redisCache) SetMultiple(ctx context.Context, items map[string]interface{}, expiration time.Duration) error {
	pipe := r.client.Pipeline()

	for key, value := range items {
		serialized, err := SerializeValue(value)
		if err != nil {
			return err
		}
		pipe.Set(ctx, key, serialized, expiration)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return NewCacheError(ErrConnection, "failed to set multiple values", err)
	}

	return nil
}

// GetMultiple retrieves multiple values from Redis
func (r *redisCache) GetMultiple(ctx context.Context, keys []string) (map[string]interface{}, error) {
	if len(keys) == 0 {
		return map[string]interface{}{}, nil
	}

	result, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, NewCacheError(ErrConnection, "failed to get multiple values", err)
	}

	values := make(map[string]interface{})
	for i, val := range result {
		if val != nil {
			values[keys[i]] = val
		}
	}

	return values, nil
}

// DeleteMultiple removes multiple keys from Redis
func (r *redisCache) DeleteMultiple(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	if err := r.client.Del(ctx, keys...).Err(); err != nil {
		return NewCacheError(ErrConnection, "failed to delete multiple keys", err)
	}

	return nil
}

// SetTTL sets the expiration time for a key
func (r *redisCache) SetTTL(ctx context.Context, key string, expiration time.Duration) error {
	if err := r.client.Expire(ctx, key, expiration).Err(); err != nil {
		return NewCacheError(ErrConnection, "failed to set TTL", err)
	}
	return nil
}

// GetTTL returns the remaining time to live for a key
func (r *redisCache) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	result, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		return 0, NewCacheError(ErrConnection, "failed to get TTL", err)
	}
	return result, nil
}

// DeleteByPattern removes all keys matching a pattern
func (r *redisCache) DeleteByPattern(ctx context.Context, pattern string) error {
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return NewCacheError(ErrConnection, "failed to get keys by pattern", err)
	}

	if len(keys) == 0 {
		return nil
	}

	return r.DeleteMultiple(ctx, keys)
}

// GetKeysByPattern returns all keys matching a pattern
func (r *redisCache) GetKeysByPattern(ctx context.Context, pattern string) ([]string, error) {
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, NewCacheError(ErrConnection, "failed to get keys by pattern", err)
	}
	return keys, nil
}

// Increment increments a counter by 1
func (r *redisCache) Increment(ctx context.Context, key string) (int64, error) {
	result, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, NewCacheError(ErrConnection, "failed to increment", err)
	}
	return result, nil
}

// IncrementBy increments a counter by the specified value
func (r *redisCache) IncrementBy(ctx context.Context, key string, value int64) (int64, error) {
	result, err := r.client.IncrBy(ctx, key, value).Result()
	if err != nil {
		return 0, NewCacheError(ErrConnection, "failed to increment by value", err)
	}
	return result, nil
}

// Decrement decrements a counter by 1
func (r *redisCache) Decrement(ctx context.Context, key string) (int64, error) {
	result, err := r.client.Decr(ctx, key).Result()
	if err != nil {
		return 0, NewCacheError(ErrConnection, "failed to decrement", err)
	}
	return result, nil
}

// DecrementBy decrements a counter by the specified value
func (r *redisCache) DecrementBy(ctx context.Context, key string, value int64) (int64, error) {
	result, err := r.client.DecrBy(ctx, key, value).Result()
	if err != nil {
		return 0, NewCacheError(ErrConnection, "failed to decrement by value", err)
	}
	return result, nil
}

// HealthCheck performs a health check on the Redis connection
func (r *redisCache) HealthCheck(ctx context.Context) error {
	return r.client.HealthCheck()
}

// redisSessionService implements SessionService using Redis
type redisSessionService struct {
	cache CacheService
}

// NewRedisSessionService creates a new Redis session service
func NewRedisSessionService(client *redisClient.Client) SessionService {
	return &redisSessionService{
		cache: NewRedisCache(client),
	}
}

// SetSession stores session data
func (r *redisSessionService) SetSession(ctx context.Context, sessionID string, data *SessionData, expiration time.Duration) error {
	key := SessionKey(sessionID)
	return r.cache.Set(ctx, key, data, expiration)
}

// GetSession retrieves session data
func (r *redisSessionService) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	key := SessionKey(sessionID)
	var data SessionData

	err := r.cache.Get(ctx, key, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

// DeleteSession removes session data
func (r *redisSessionService) DeleteSession(ctx context.Context, sessionID string) error {
	key := SessionKey(sessionID)
	return r.cache.Delete(ctx, key)
}

// RefreshSession extends session expiration
func (r *redisSessionService) RefreshSession(ctx context.Context, sessionID string, expiration time.Duration) error {
	key := SessionKey(sessionID)
	return r.cache.SetTTL(ctx, key, expiration)
}

// SetUserSessions stores the list of session IDs for a user
func (r *redisSessionService) SetUserSessions(ctx context.Context, userID int64, sessionIDs []string) error {
	key := UserSessionKey(userID)
	return r.cache.Set(ctx, key, sessionIDs, 7*24*time.Hour) // 7 days
}

// GetUserSessions retrieves the list of session IDs for a user
func (r *redisSessionService) GetUserSessions(ctx context.Context, userID int64) ([]string, error) {
	key := UserSessionKey(userID)
	var sessionIDs []string

	err := r.cache.Get(ctx, key, &sessionIDs)
	if IsNotFoundError(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}

	return sessionIDs, nil
}

// DeleteUserSessions removes all session data for a user
func (r *redisSessionService) DeleteUserSessions(ctx context.Context, userID int64) error {
	// Get user sessions
	sessionIDs, err := r.GetUserSessions(ctx, userID)
	if err != nil {
		return err
	}

	// Delete individual sessions
	for _, sessionID := range sessionIDs {
		if err := r.DeleteSession(ctx, sessionID); err != nil {
			// Log error but continue with other sessions
			continue
		}
	}

	// Delete user sessions list
	key := UserSessionKey(userID)
	return r.cache.Delete(ctx, key)
}

// BlacklistToken adds a token to the blacklist
func (r *redisSessionService) BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error {
	key := BlacklistKey(tokenID)
	return r.cache.Set(ctx, key, "blacklisted", expiration)
}

// IsTokenBlacklisted checks if a token is blacklisted
func (r *redisSessionService) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	key := BlacklistKey(tokenID)
	return r.cache.Exists(ctx, key)
}

// GetActiveSessionCount returns the total number of active sessions
func (r *redisSessionService) GetActiveSessionCount(ctx context.Context) (int64, error) {
	pattern := SessionKeyPrefix + "*"
	keys, err := r.cache.GetKeysByPattern(ctx, pattern)
	if err != nil {
		return 0, err
	}
	return int64(len(keys)), nil
}

// GetUserSessionCount returns the number of active sessions for a user
func (r *redisSessionService) GetUserSessionCount(ctx context.Context, userID int64) (int64, error) {
	sessionIDs, err := r.GetUserSessions(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int64(len(sessionIDs)), nil
}
