package redis

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.URL != "localhost:6379" {
		t.Errorf("Expected URL to be localhost:6379, got %s", config.URL)
	}

	if config.Password != "" {
		t.Errorf("Expected Password to be empty, got %s", config.Password)
	}

	if config.DB != 0 {
		t.Errorf("Expected DB to be 0, got %d", config.DB)
	}

	if config.MaxRetries != 3 {
		t.Errorf("Expected MaxRetries to be 3, got %d", config.MaxRetries)
	}

	if config.MinIdleConns != 5 {
		t.Errorf("Expected MinIdleConns to be 5, got %d", config.MinIdleConns)
	}

	if config.MaxIdleConns != 10 {
		t.Errorf("Expected MaxIdleConns to be 10, got %d", config.MaxIdleConns)
	}

	if config.ConnMaxLifetime != 30*time.Minute {
		t.Errorf("Expected ConnMaxLifetime to be 30m, got %v", config.ConnMaxLifetime)
	}

	if config.PoolTimeout != 4*time.Second {
		t.Errorf("Expected PoolTimeout to be 4s, got %v", config.PoolTimeout)
	}

	if config.IdleTimeout != 5*time.Minute {
		t.Errorf("Expected IdleTimeout to be 5m, got %v", config.IdleTimeout)
	}

	if config.ReadTimeout != 3*time.Second {
		t.Errorf("Expected ReadTimeout to be 3s, got %v", config.ReadTimeout)
	}

	if config.WriteTimeout != 3*time.Second {
		t.Errorf("Expected WriteTimeout to be 3s, got %v", config.WriteTimeout)
	}
}

func TestNewClientWithNilConfig(t *testing.T) {
	// This test requires a Redis server running on localhost:6379
	// Skip if Redis is not available
	client, err := NewClient(nil)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer client.Close()

	if client.config.URL != "localhost:6379" {
		t.Errorf("Expected URL to be localhost:6379, got %s", client.config.URL)
	}
}

func TestNewClientWithCustomConfig(t *testing.T) {
	config := &Config{
		URL:             "localhost:6380",
		Password:        "testpass",
		DB:              1,
		MaxRetries:      5,
		MinIdleConns:    2,
		MaxIdleConns:    8,
		ConnMaxLifetime: 15 * time.Minute,
		PoolTimeout:     2 * time.Second,
		IdleTimeout:     3 * time.Minute,
		ReadTimeout:     1 * time.Second,
		WriteTimeout:    1 * time.Second,
	}

	// This will likely fail since we don't have Redis on port 6380
	// but we can test that the config is properly set
	client, err := NewClient(config)
	if err != nil {
		// Expected since Redis is not running on 6380
		return
	}
	defer client.Close()

	if client.config.URL != "localhost:6380" {
		t.Errorf("Expected URL to be localhost:6380, got %s", client.config.URL)
	}

	if client.config.Password != "testpass" {
		t.Errorf("Expected Password to be testpass, got %s", client.config.Password)
	}

	if client.config.DB != 1 {
		t.Errorf("Expected DB to be 1, got %d", client.config.DB)
	}
}

// Integration tests - these require a Redis server to be running
func TestRedisClientIntegration(t *testing.T) {
	config := DefaultConfig()
	client, err := NewClient(config)
	if err != nil {
		t.Skipf("Redis not available for integration test: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	t.Run("Ping", func(t *testing.T) {
		err := client.Ping()
		if err != nil {
			t.Errorf("Ping failed: %v", err)
		}
	})

	t.Run("HealthCheck", func(t *testing.T) {
		err := client.HealthCheck()
		if err != nil {
			t.Errorf("HealthCheck failed: %v", err)
		}
	})

	t.Run("IsConnected", func(t *testing.T) {
		connected := client.IsConnected()
		if !connected {
			t.Error("Expected client to be connected")
		}
	})

	t.Run("BasicOperations", func(t *testing.T) {
		// Test basic set/get operations
		testKey := "test_key_" + time.Now().Format("20060102150405")
		testValue := "test_value"

		// Set value
		err := client.Set(ctx, testKey, testValue, time.Minute).Err()
		if err != nil {
			t.Errorf("Set operation failed: %v", err)
		}

		// Get value
		result, err := client.Get(ctx, testKey).Result()
		if err != nil {
			t.Errorf("Get operation failed: %v", err)
		}

		if result != testValue {
			t.Errorf("Expected %s, got %s", testValue, result)
		}

		// Delete value
		err = client.Del(ctx, testKey).Err()
		if err != nil {
			t.Errorf("Delete operation failed: %v", err)
		}
	})

	t.Run("GetStats", func(t *testing.T) {
		stats := client.GetStats()
		if stats == nil {
			t.Error("Expected stats to be non-nil")
		}
	})

	t.Run("WithContext", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		contextClient := client.WithContext(ctx)
		if contextClient == nil {
			t.Error("Expected WithContext to return non-nil client")
		}

		// Test that the context is properly used
		err := contextClient.Ping()
		if err != nil {
			t.Errorf("Ping with context failed: %v", err)
		}
	})

	t.Run("GetConfig", func(t *testing.T) {
		returnedConfig := client.GetConfig()
		if returnedConfig == nil {
			t.Error("Expected GetConfig to return non-nil config")
		}

		if returnedConfig.URL != config.URL {
			t.Errorf("Expected URL %s, got %s", config.URL, returnedConfig.URL)
		}
	})
}

func TestRedisClientFailureScenarios(t *testing.T) {
	t.Run("InvalidURL", func(t *testing.T) {
		config := &Config{
			URL:      "invalid:99999",
			Password: "",
			DB:       0,
		}

		client, err := NewClient(config)
		if err == nil {
			client.Close()
			t.Error("Expected NewClient to fail with invalid URL")
		}
	})

	t.Run("PingFailure", func(t *testing.T) {
		// Create client that will fail to connect
		config := &Config{
			URL:         "localhost:99999", // Non-existent port
			Password:    "",
			DB:          0,
			MaxRetries:  1,
			ReadTimeout: 100 * time.Millisecond,
		}

		client, err := NewClient(config)
		if err == nil {
			defer client.Close()
			t.Error("Expected NewClient to fail with non-existent Redis")
		}
	})
}

// Benchmark tests
func BenchmarkRedisClient(b *testing.B) {
	config := DefaultConfig()
	client, err := NewClient(config)
	if err != nil {
		b.Skipf("Redis not available for benchmark: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	b.Run("Ping", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			client.Ping()
		}
	})

	b.Run("SetGet", func(b *testing.B) {
		testKey := "bench_key"
		testValue := "bench_value"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			client.Set(ctx, testKey, testValue, time.Minute)
			client.Get(ctx, testKey)
		}
	})

	b.Run("HealthCheck", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			client.HealthCheck()
		}
	})
}
