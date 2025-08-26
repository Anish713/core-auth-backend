package ratelimit

import (
	"context"
	"fmt"
	"time"

	"auth-service/pkg/cache"
	redisClient "auth-service/pkg/redis"
)

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	// Allow checks if a request is allowed under the rate limit
	Allow(ctx context.Context, identifier string) (bool, error)

	// AllowN checks if N requests are allowed under the rate limit
	AllowN(ctx context.Context, identifier string, n int) (bool, error)

	// Reset resets the rate limit for an identifier
	Reset(ctx context.Context, identifier string) error

	// GetUsage returns the current usage for an identifier
	GetUsage(ctx context.Context, identifier string) (*Usage, error)

	// SetLimit dynamically updates the rate limit for an identifier
	SetLimit(ctx context.Context, identifier string, limit int, window time.Duration) error
}

// Usage represents the current usage information
type Usage struct {
	Identifier string        `json:"identifier"`
	Current    int           `json:"current"`
	Limit      int           `json:"limit"`
	Window     time.Duration `json:"window"`
	ResetTime  time.Time     `json:"reset_time"`
	Remaining  int           `json:"remaining"`
}

// Config represents rate limiter configuration
type Config struct {
	Limit      int           // Maximum number of requests
	Window     time.Duration // Time window for the limit
	Identifier string        // Base identifier for grouping
}

// redisRateLimiter implements RateLimiter using Redis
type redisRateLimiter struct {
	cache  cache.CacheService
	config *Config
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(client *redisClient.Client, config *Config) RateLimiter {
	return &redisRateLimiter{
		cache:  cache.NewRedisCache(client),
		config: config,
	}
}

// Allow checks if a single request is allowed
func (r *redisRateLimiter) Allow(ctx context.Context, identifier string) (bool, error) {
	return r.AllowN(ctx, identifier, 1)
}

// AllowN checks if N requests are allowed using sliding window log algorithm
func (r *redisRateLimiter) AllowN(ctx context.Context, identifier string, n int) (bool, error) {
	key := r.buildKey(identifier)
	now := time.Now()
	windowStart := now.Add(-r.config.Window)

	// Get current request timestamps
	var timestamps []int64
	err := r.cache.Get(ctx, key, &timestamps)
	if err != nil && !cache.IsNotFoundError(err) {
		return false, fmt.Errorf("failed to get rate limit data: %w", err)
	}

	// Filter out expired timestamps
	validTimestamps := make([]int64, 0, len(timestamps))
	for _, ts := range timestamps {
		if time.Unix(0, ts).After(windowStart) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	// Check if adding N requests would exceed the limit
	if len(validTimestamps)+n > r.config.Limit {
		// Update with current valid timestamps (cleanup)
		if err := r.updateTimestamps(ctx, key, validTimestamps); err != nil {
			return false, fmt.Errorf("failed to update timestamps: %w", err)
		}
		return false, nil
	}

	// Add N new timestamps
	for i := 0; i < n; i++ {
		validTimestamps = append(validTimestamps, now.Add(time.Duration(i)*time.Nanosecond).UnixNano())
	}

	// Store updated timestamps with expiration
	if err := r.updateTimestamps(ctx, key, validTimestamps); err != nil {
		return false, fmt.Errorf("failed to update timestamps: %w", err)
	}

	return true, nil
}

// Reset resets the rate limit for an identifier
func (r *redisRateLimiter) Reset(ctx context.Context, identifier string) error {
	key := r.buildKey(identifier)
	return r.cache.Delete(ctx, key)
}

// GetUsage returns current usage information
func (r *redisRateLimiter) GetUsage(ctx context.Context, identifier string) (*Usage, error) {
	key := r.buildKey(identifier)
	now := time.Now()
	windowStart := now.Add(-r.config.Window)

	var timestamps []int64
	err := r.cache.Get(ctx, key, &timestamps)
	if err != nil && !cache.IsNotFoundError(err) {
		return nil, fmt.Errorf("failed to get rate limit data: %w", err)
	}

	// Count valid timestamps
	current := 0
	for _, ts := range timestamps {
		if time.Unix(0, ts).After(windowStart) {
			current++
		}
	}

	remaining := r.config.Limit - current
	if remaining < 0 {
		remaining = 0
	}

	return &Usage{
		Identifier: identifier,
		Current:    current,
		Limit:      r.config.Limit,
		Window:     r.config.Window,
		ResetTime:  now.Add(r.config.Window),
		Remaining:  remaining,
	}, nil
}

// SetLimit dynamically updates the rate limit (not implemented in basic version)
func (r *redisRateLimiter) SetLimit(ctx context.Context, identifier string, limit int, window time.Duration) error {
	// For dynamic limits, we would need a more complex implementation
	// This could store per-identifier configurations
	return fmt.Errorf("dynamic limits not implemented in this version")
}

// buildKey creates a cache key for the rate limiter
func (r *redisRateLimiter) buildKey(identifier string) string {
	return cache.RateLimitKey(fmt.Sprintf("%s:%s", r.config.Identifier, identifier))
}

// updateTimestamps stores timestamps with proper expiration
func (r *redisRateLimiter) updateTimestamps(ctx context.Context, key string, timestamps []int64) error {
	// Set expiration to window duration + buffer
	expiration := r.config.Window + time.Minute
	return r.cache.Set(ctx, key, timestamps, expiration)
}

// TokenBucketLimiter implements a token bucket rate limiter
type TokenBucketLimiter struct {
	cache        cache.CacheService
	capacity     int           // Bucket capacity
	refillRate   int           // Tokens refilled per second
	refillPeriod time.Duration // How often to refill
	identifier   string        // Base identifier
}

// TokenBucketData represents the state of a token bucket
type TokenBucketData struct {
	Tokens     int       `json:"tokens"`
	LastRefill time.Time `json:"last_refill"`
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(client *redisClient.Client, capacity, refillRate int, identifier string) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		cache:        cache.NewRedisCache(client),
		capacity:     capacity,
		refillRate:   refillRate,
		refillPeriod: time.Second,
		identifier:   identifier,
	}
}

// Allow checks if a request is allowed using token bucket algorithm
func (t *TokenBucketLimiter) Allow(ctx context.Context, identifier string) (bool, error) {
	return t.AllowN(ctx, identifier, 1)
}

// AllowN checks if N tokens are available
func (t *TokenBucketLimiter) AllowN(ctx context.Context, identifier string, n int) (bool, error) {
	key := t.buildKey(identifier)
	now := time.Now()

	// Get current bucket state
	var bucket TokenBucketData
	err := t.cache.Get(ctx, key, &bucket)
	if err != nil && !cache.IsNotFoundError(err) {
		return false, fmt.Errorf("failed to get bucket data: %w", err)
	}

	// Initialize bucket if not found
	if cache.IsNotFoundError(err) {
		bucket = TokenBucketData{
			Tokens:     t.capacity,
			LastRefill: now,
		}
	}

	// Calculate tokens to add based on elapsed time
	elapsed := now.Sub(bucket.LastRefill)
	tokensToAdd := int(elapsed.Seconds()) * t.refillRate
	bucket.Tokens += tokensToAdd

	// Cap at bucket capacity
	if bucket.Tokens > t.capacity {
		bucket.Tokens = t.capacity
	}

	bucket.LastRefill = now

	// Check if we have enough tokens
	if bucket.Tokens < n {
		// Update bucket state even if request is denied
		if err := t.updateBucket(ctx, key, &bucket); err != nil {
			return false, fmt.Errorf("failed to update bucket: %w", err)
		}
		return false, nil
	}

	// Consume tokens
	bucket.Tokens -= n

	// Update bucket state
	if err := t.updateBucket(ctx, key, &bucket); err != nil {
		return false, fmt.Errorf("failed to update bucket: %w", err)
	}

	return true, nil
}

// Reset resets the token bucket
func (t *TokenBucketLimiter) Reset(ctx context.Context, identifier string) error {
	key := t.buildKey(identifier)
	return t.cache.Delete(ctx, key)
}

// GetUsage returns current bucket usage
func (t *TokenBucketLimiter) GetUsage(ctx context.Context, identifier string) (*Usage, error) {
	key := t.buildKey(identifier)
	now := time.Now()

	var bucket TokenBucketData
	err := t.cache.Get(ctx, key, &bucket)
	if err != nil && !cache.IsNotFoundError(err) {
		return nil, fmt.Errorf("failed to get bucket data: %w", err)
	}

	if cache.IsNotFoundError(err) {
		bucket = TokenBucketData{
			Tokens:     t.capacity,
			LastRefill: now,
		}
	}

	// Calculate current tokens
	elapsed := now.Sub(bucket.LastRefill)
	tokensToAdd := int(elapsed.Seconds()) * t.refillRate
	currentTokens := bucket.Tokens + tokensToAdd
	if currentTokens > t.capacity {
		currentTokens = t.capacity
	}

	return &Usage{
		Identifier: identifier,
		Current:    t.capacity - currentTokens, // Used tokens
		Limit:      t.capacity,
		Window:     t.refillPeriod,
		ResetTime:  now.Add(time.Duration(t.capacity/t.refillRate) * time.Second),
		Remaining:  currentTokens,
	}, nil
}

// buildKey creates a cache key for the token bucket
func (t *TokenBucketLimiter) buildKey(identifier string) string {
	return cache.RateLimitKey(fmt.Sprintf("bucket:%s:%s", t.identifier, identifier))
}

// updateBucket stores bucket state with expiration
func (t *TokenBucketLimiter) updateBucket(ctx context.Context, key string, bucket *TokenBucketData) error {
	// Expire after some time of inactivity
	expiration := 10 * time.Minute
	return t.cache.Set(ctx, key, bucket, expiration)
}
