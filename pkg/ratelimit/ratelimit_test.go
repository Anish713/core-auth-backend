package ratelimit

import (
	"context"
	"testing"
	"time"

	"auth-service/pkg/redis"
)

func TestRateLimiterConfig(t *testing.T) {
	config := &Config{
		Limit:      10,
		Window:     time.Minute,
		Identifier: "test",
	}

	if config.Limit != 10 {
		t.Errorf("Expected Limit to be 10, got %d", config.Limit)
	}

	if config.Window != time.Minute {
		t.Errorf("Expected Window to be 1 minute, got %v", config.Window)
	}

	if config.Identifier != "test" {
		t.Errorf("Expected Identifier to be 'test', got %s", config.Identifier)
	}
}

func TestUsage(t *testing.T) {
	usage := &Usage{
		Identifier: "test_user",
		Current:    5,
		Limit:      10,
		Window:     time.Minute,
		ResetTime:  time.Now().Add(time.Minute),
		Remaining:  5,
	}

	if usage.Current != 5 {
		t.Errorf("Expected Current to be 5, got %d", usage.Current)
	}

	if usage.Remaining != 5 {
		t.Errorf("Expected Remaining to be 5, got %d", usage.Remaining)
	}

	if usage.Limit != 10 {
		t.Errorf("Expected Limit to be 10, got %d", usage.Limit)
	}
}

// Integration tests for Redis rate limiter
func TestRedisRateLimiterIntegration(t *testing.T) {
	// Setup Redis client
	config := redis.DefaultConfig()
	client, err := redis.NewClient(config)
	if err != nil {
		t.Skipf("Redis not available for integration test: %v", err)
	}
	defer client.Close()

	rateLimitConfig := &Config{
		Limit:      5,
		Window:     time.Minute,
		Identifier: "test",
	}

	limiter := NewRedisRateLimiter(client, rateLimitConfig)
	ctx := context.Background()
	identifier := "test_user_" + time.Now().Format("20060102150405")

	t.Run("AllowWithinLimit", func(t *testing.T) {
		// Reset rate limit
		limiter.Reset(ctx, identifier+"_1")

		// Should allow requests within limit
		for i := 0; i < rateLimitConfig.Limit; i++ {
			allowed, err := limiter.Allow(ctx, identifier+"_1")
			if err != nil {
				t.Errorf("Allow failed: %v", err)
			}
			if !allowed {
				t.Errorf("Expected request %d to be allowed", i+1)
			}
		}
	})

	t.Run("DenyBeyondLimit", func(t *testing.T) {
		// Reset rate limit
		limiter.Reset(ctx, identifier+"_2")

		// Use up the limit
		for i := 0; i < rateLimitConfig.Limit; i++ {
			limiter.Allow(ctx, identifier+"_2")
		}

		// This should be denied
		allowed, err := limiter.Allow(ctx, identifier+"_2")
		if err != nil {
			t.Errorf("Allow failed: %v", err)
		}
		if allowed {
			t.Error("Expected request to be denied when over limit")
		}
	})

	t.Run("AllowN", func(t *testing.T) {
		// Reset rate limit
		limiter.Reset(ctx, identifier+"_3")

		// Should allow N requests at once if within limit
		allowed, err := limiter.AllowN(ctx, identifier+"_3", 3)
		if err != nil {
			t.Errorf("AllowN failed: %v", err)
		}
		if !allowed {
			t.Error("Expected AllowN(3) to be allowed")
		}

		// Should deny if requesting more than remaining
		allowed, err = limiter.AllowN(ctx, identifier+"_3", 3)
		if err != nil {
			t.Errorf("AllowN failed: %v", err)
		}
		if allowed {
			t.Error("Expected AllowN(3) to be denied when would exceed limit")
		}
	})

	t.Run("GetUsage", func(t *testing.T) {
		// Reset rate limit
		limiter.Reset(ctx, identifier+"_4")

		// Use some requests
		limiter.AllowN(ctx, identifier+"_4", 3)

		usage, err := limiter.GetUsage(ctx, identifier+"_4")
		if err != nil {
			t.Errorf("GetUsage failed: %v", err)
		}

		if usage.Identifier != identifier+"_4" {
			t.Errorf("Expected identifier %s, got %s", identifier+"_4", usage.Identifier)
		}

		if usage.Current != 3 {
			t.Errorf("Expected current usage to be 3, got %d", usage.Current)
		}

		if usage.Limit != rateLimitConfig.Limit {
			t.Errorf("Expected limit to be %d, got %d", rateLimitConfig.Limit, usage.Limit)
		}

		if usage.Remaining != rateLimitConfig.Limit-3 {
			t.Errorf("Expected remaining to be %d, got %d", rateLimitConfig.Limit-3, usage.Remaining)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		// Use up the limit
		for i := 0; i < rateLimitConfig.Limit; i++ {
			limiter.Allow(ctx, identifier+"_5")
		}

		// Should be denied
		allowed, _ := limiter.Allow(ctx, identifier+"_5")
		if allowed {
			t.Error("Expected request to be denied before reset")
		}

		// Reset
		err := limiter.Reset(ctx, identifier+"_5")
		if err != nil {
			t.Errorf("Reset failed: %v", err)
		}

		// Should be allowed again
		allowed, err = limiter.Allow(ctx, identifier+"_5")
		if err != nil {
			t.Errorf("Allow failed after reset: %v", err)
		}
		if !allowed {
			t.Error("Expected request to be allowed after reset")
		}
	})

	t.Run("SlidingWindow", func(t *testing.T) {
		// Test with a shorter window for faster testing
		shortConfig := &Config{
			Limit:      2,
			Window:     2 * time.Second,
			Identifier: "short_test",
		}
		shortLimiter := NewRedisRateLimiter(client, shortConfig)

		// Reset
		shortLimiter.Reset(ctx, identifier+"_6")

		// Use up the limit
		shortLimiter.AllowN(ctx, identifier+"_6", 2)

		// Should be denied
		allowed, _ := shortLimiter.Allow(ctx, identifier+"_6")
		if allowed {
			t.Error("Expected request to be denied when limit reached")
		}

		// Wait for window to expire
		time.Sleep(3 * time.Second)

		// Should be allowed again after window expires
		allowed, err = shortLimiter.Allow(ctx, identifier+"_6")
		if err != nil {
			t.Errorf("Allow failed after window expiry: %v", err)
		}
		if !allowed {
			t.Error("Expected request to be allowed after window expiry")
		}
	})
}

func TestTokenBucketLimiterIntegration(t *testing.T) {
	// Setup Redis client
	config := redis.DefaultConfig()
	client, err := redis.NewClient(config)
	if err != nil {
		t.Skipf("Redis not available for integration test: %v", err)
	}
	defer client.Close()

	capacity := 5
	refillRate := 2 // 2 tokens per second
	limiter := NewTokenBucketLimiter(client, capacity, refillRate, "test_bucket")
	ctx := context.Background()
	identifier := "bucket_user_" + time.Now().Format("20060102150405")

	t.Run("InitialCapacity", func(t *testing.T) {
		// Reset bucket
		limiter.Reset(ctx, identifier+"_1")

		// Should be able to consume all initial tokens
		for i := 0; i < capacity; i++ {
			allowed, err := limiter.Allow(ctx, identifier+"_1")
			if err != nil {
				t.Errorf("Allow failed: %v", err)
			}
			if !allowed {
				t.Errorf("Expected request %d to be allowed", i+1)
			}
		}

		// Next request should be denied
		allowed, err := limiter.Allow(ctx, identifier+"_1")
		if err != nil {
			t.Errorf("Allow failed: %v", err)
		}
		if allowed {
			t.Error("Expected request to be denied when bucket is empty")
		}
	})

	t.Run("TokenRefill", func(t *testing.T) {
		// Reset bucket
		limiter.Reset(ctx, identifier+"_2")

		// Consume all tokens
		limiter.AllowN(ctx, identifier+"_2", capacity)

		// Should be denied immediately
		allowed, _ := limiter.Allow(ctx, identifier+"_2")
		if allowed {
			t.Error("Expected request to be denied when bucket is empty")
		}

		// Wait for refill (refillRate tokens per second)
		time.Sleep(1100 * time.Millisecond) // Wait a bit more than 1 second

		// Should have refilled tokens
		allowed, err := limiter.Allow(ctx, identifier+"_2")
		if err != nil {
			t.Errorf("Allow failed after refill: %v", err)
		}
		if !allowed {
			t.Error("Expected request to be allowed after token refill")
		}
	})

	t.Run("GetUsage", func(t *testing.T) {
		// Reset bucket
		limiter.Reset(ctx, identifier+"_3")

		// Consume some tokens
		limiter.AllowN(ctx, identifier+"_3", 2)

		usage, err := limiter.GetUsage(ctx, identifier+"_3")
		if err != nil {
			t.Errorf("GetUsage failed: %v", err)
		}

		if usage.Identifier != identifier+"_3" {
			t.Errorf("Expected identifier %s, got %s", identifier+"_3", usage.Identifier)
		}

		if usage.Current != 2 {
			t.Errorf("Expected current usage to be 2, got %d", usage.Current)
		}

		if usage.Limit != capacity {
			t.Errorf("Expected limit to be %d, got %d", capacity, usage.Limit)
		}

		if usage.Remaining != capacity-2 {
			t.Errorf("Expected remaining to be %d, got %d", capacity-2, usage.Remaining)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		// Consume all tokens
		limiter.AllowN(ctx, identifier+"_4", capacity)

		// Should be denied
		allowed, _ := limiter.Allow(ctx, identifier+"_4")
		if allowed {
			t.Error("Expected request to be denied before reset")
		}

		// Reset
		err := limiter.Reset(ctx, identifier+"_4")
		if err != nil {
			t.Errorf("Reset failed: %v", err)
		}

		// Should be allowed again
		allowed, err = limiter.Allow(ctx, identifier+"_4")
		if err != nil {
			t.Errorf("Allow failed after reset: %v", err)
		}
		if !allowed {
			t.Error("Expected request to be allowed after reset")
		}
	})

	t.Run("AllowN", func(t *testing.T) {
		// Reset bucket
		limiter.Reset(ctx, identifier+"_5")

		// Should allow consuming multiple tokens at once
		allowed, err := limiter.AllowN(ctx, identifier+"_5", 3)
		if err != nil {
			t.Errorf("AllowN failed: %v", err)
		}
		if !allowed {
			t.Error("Expected AllowN(3) to be allowed")
		}

		// Should deny if requesting more than available
		allowed, err = limiter.AllowN(ctx, identifier+"_5", 3)
		if err != nil {
			t.Errorf("AllowN failed: %v", err)
		}
		if allowed {
			t.Error("Expected AllowN(3) to be denied when insufficient tokens")
		}
	})
}

// Performance/benchmark tests
func BenchmarkRedisRateLimiter(b *testing.B) {
	config := redis.DefaultConfig()
	client, err := redis.NewClient(config)
	if err != nil {
		b.Skipf("Redis not available for benchmark: %v", err)
	}
	defer client.Close()

	rateLimitConfig := &Config{
		Limit:      1000,
		Window:     time.Minute,
		Identifier: "bench",
	}

	limiter := NewRedisRateLimiter(client, rateLimitConfig)
	ctx := context.Background()

	b.Run("Allow", func(b *testing.B) {
		identifier := "bench_allow"
		limiter.Reset(ctx, identifier)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			limiter.Allow(ctx, identifier)
		}
	})

	b.Run("GetUsage", func(b *testing.B) {
		identifier := "bench_usage"
		limiter.Reset(ctx, identifier)
		limiter.AllowN(ctx, identifier, 10) // Add some usage

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			limiter.GetUsage(ctx, identifier)
		}
	})
}

func BenchmarkTokenBucketLimiter(b *testing.B) {
	config := redis.DefaultConfig()
	client, err := redis.NewClient(config)
	if err != nil {
		b.Skipf("Redis not available for benchmark: %v", err)
	}
	defer client.Close()

	limiter := NewTokenBucketLimiter(client, 1000, 100, "bench_bucket")
	ctx := context.Background()

	b.Run("Allow", func(b *testing.B) {
		identifier := "bench_bucket_allow"
		limiter.Reset(ctx, identifier)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			limiter.Allow(ctx, identifier)
		}
	})

	b.Run("GetUsage", func(b *testing.B) {
		identifier := "bench_bucket_usage"
		limiter.Reset(ctx, identifier)
		limiter.AllowN(ctx, identifier, 10) // Add some usage

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			limiter.GetUsage(ctx, identifier)
		}
	})
}
