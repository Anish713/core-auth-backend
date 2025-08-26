package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps the Redis client with additional functionality
type Client struct {
	*redis.Client
	config *Config
}

// Config holds Redis configuration
type Config struct {
	URL      string
	Password string
	DB       int
	// Connection pool settings
	MaxRetries      int
	MinIdleConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	PoolTimeout     time.Duration
	IdleTimeout     time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
}

// DefaultConfig returns default Redis configuration
func DefaultConfig() *Config {
	return &Config{
		URL:             "localhost:6379",
		Password:        "",
		DB:              0,
		MaxRetries:      3,
		MinIdleConns:    5,
		MaxIdleConns:    10,
		ConnMaxLifetime: 30 * time.Minute,
		PoolTimeout:     4 * time.Second,
		IdleTimeout:     5 * time.Minute,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
	}
}

// NewClient creates a new Redis client with the given configuration
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	opts := &redis.Options{
		Addr:            config.URL,
		Password:        config.Password,
		DB:              config.DB,
		MaxRetries:      config.MaxRetries,
		MinIdleConns:    config.MinIdleConns,
		MaxIdleConns:    config.MaxIdleConns,
		ConnMaxLifetime: config.ConnMaxLifetime,
		PoolTimeout:     config.PoolTimeout,
		ReadTimeout:     config.ReadTimeout,
		WriteTimeout:    config.WriteTimeout,
	}

	rdb := redis.NewClient(opts)

	client := &Client{
		Client: rdb,
		config: config,
	}

	// Test the connection
	if err := client.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return client, nil
}

// Ping tests the Redis connection
func (c *Client) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := c.Client.Ping(ctx)
	return result.Err()
}

// HealthCheck performs a comprehensive health check
func (c *Client) HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test basic connectivity
	if err := c.Client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Test read/write operations
	testKey := "health_check_" + fmt.Sprintf("%d", time.Now().UnixNano())
	testValue := "ok"

	// Set a test value
	if err := c.Client.Set(ctx, testKey, testValue, time.Second).Err(); err != nil {
		return fmt.Errorf("set operation failed: %w", err)
	}

	// Get the test value
	result, err := c.Client.Get(ctx, testKey).Result()
	if err != nil {
		return fmt.Errorf("get operation failed: %w", err)
	}

	if result != testValue {
		return fmt.Errorf("value mismatch: expected %s, got %s", testValue, result)
	}

	// Clean up
	c.Client.Del(ctx, testKey)

	return nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.Client.Close()
}

// GetStats returns connection pool statistics
func (c *Client) GetStats() *redis.PoolStats {
	return c.Client.PoolStats()
}

// WithContext returns a new client with the given context
func (c *Client) WithContext(ctx context.Context) *Client {
	return &Client{
		Client: c.Client, // Redis client doesn't have WithContext method
		config: c.config,
	}
}

// IsConnected checks if the client is connected to Redis
func (c *Client) IsConnected() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := c.Client.Ping(ctx).Err()
	return err == nil
}

// GetConfig returns the current configuration
func (c *Client) GetConfig() *Config {
	return c.config
}
