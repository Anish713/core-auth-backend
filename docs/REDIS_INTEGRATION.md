# Redis Session Management Integration

This document describes the Redis-based session management system integrated into the authentication service.

## Overview

The Redis integration provides:

- **Distributed Caching**: Store session data across multiple server instances
- **Session Management**: Track and manage user sessions with automatic cleanup
- **Rate Limiting**: Prevent abuse with Redis-backed distributed rate limiting
- **Token Blacklisting**: Security feature for invalidated tokens
- **Health Monitoring**: Redis connectivity monitoring

## Architecture

### Components

1. **Redis Client** (`pkg/redis/`)

   - Connection management with pooling
   - Health checks and monitoring
   - Graceful error handling

2. **Cache Service** (`pkg/cache/`)

   - Generic cache interface
   - Redis implementation
   - Session-specific operations

3. **Rate Limiting** (`pkg/ratelimit/`)

   - Sliding window algorithm
   - Token bucket algorithm
   - Distributed rate limiting

4. **Session Manager** (`internal/services/session_service.go`)
   - User session lifecycle management
   - Session monitoring and cleanup
   - Token blacklisting

## Configuration

### Environment Variables

```env
# Redis Configuration
REDIS_ENABLED=true
REDIS_URL=redis-16044.c92.us-east-1-3.ec2.redns.redis-cloud.com:16044
REDIS_PASSWORD=your_redis_password_here
REDIS_DB=0
```

### Application Configuration

The Redis client is configured in `main.go` with the following settings:

```go
redisConfig := &redis.Config{
    URL:             cfg.RedisURL,
    Password:        cfg.RedisPassword,
    DB:              cfg.RedisDB,
    MaxRetries:      3,
    MinIdleConns:    5,
    MaxIdleConns:    10,
    ConnMaxLifetime: 30 * time.Minute,
    PoolTimeout:     4 * time.Second,
    ReadTimeout:     3 * time.Second,
    WriteTimeout:    3 * time.Second,
}
```

## API Endpoints

### Authentication Endpoints

#### Sign In

- **POST** `/api/v1/auth/signin`
- Creates a new session automatically
- Returns session ID in `X-Session-ID` header

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Sign Out

- **POST** `/api/v1/auth/signout`
- Requires: `Authorization: Bearer <token>`
- Optional: `X-Session-ID: <session-id>`
- Cleans up session and blacklists token

### Session Management Endpoints

#### List Active Sessions

- **GET** `/api/v1/sessions`
- Requires: `Authorization: Bearer <token>`
- Returns all active sessions for the current user

```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": "session-123",
        "user_id": 456,
        "email": "user@example.com",
        "created_at": "2024-01-15T10:30:00Z",
        "last_access": "2024-01-15T11:45:00Z",
        "expires_at": "2024-01-16T10:30:00Z",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "is_active": true
      }
    ],
    "count": 1
  }
}
```

#### Terminate Specific Session

- **DELETE** `/api/v1/sessions/:sessionId`
- Requires: `Authorization: Bearer <token>`
- Terminates the specified session

#### Terminate All Sessions

- **DELETE** `/api/v1/sessions`
- Requires: `Authorization: Bearer <token>`
- Optional: `X-Session-ID: <current-session-id>`
- Terminates all user sessions except the current one

## Session Management Features

### Automatic Session Creation

When a user signs in, a session is automatically created with:

- Unique session ID (64-character hex string)
- User metadata (IP address, user agent)
- Configurable expiration time
- Session activity tracking

### Session Limitations

- Maximum 5 sessions per user (configurable)
- Oldest sessions are automatically removed when limit is exceeded
- Sessions expire after 24 hours by default

### Token Blacklisting

When users sign out or sessions are terminated:

- JWT tokens are added to a blacklist
- Blacklisted tokens are rejected even if not expired
- Automatic cleanup of expired blacklist entries

### Session Activity Tracking

Each session tracks:

- Request count
- Last request time
- Session duration
- IP addresses used

## Rate Limiting

### Redis-Based Rate Limiting

- Replaces in-memory rate limiting
- Distributed across multiple server instances
- Configurable limits and time windows

### Configuration

```go
rateLimitConfig := &ratelimit.Config{
    Limit:      10,          // 10 requests
    Window:     time.Minute, // per minute
    Identifier: "api",       // limiter identifier
}
```

### Headers

Rate limit information is returned in response headers:

- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Time when limit resets

## Health Monitoring

### Health Check Endpoints

- **GET** `/health` - Basic health check
- **GET** `/ready` - Readiness check including Redis connectivity

### Redis Health Check

The `/ready` endpoint performs comprehensive Redis health checks:

- Basic connectivity test
- Read/write operation test
- Connection pool status

## Error Handling

### Graceful Degradation

- Application continues to work if Redis is unavailable
- Session management is disabled but authentication still works
- Rate limiting falls back to basic limits

### Error Responses

```json
{
  "success": false,
  "error": {
    "code": "SESSION_ERROR",
    "message": "Session operation failed"
  }
}
```

## Security Considerations

### Token Security

- Tokens are blacklisted on sign out
- Automatic cleanup of expired tokens
- Session validation on each request

### Session Security

- Secure session ID generation
- IP address tracking
- User agent validation
- Configurable session limits

## Performance Optimization

### Connection Pooling

- Configurable min/max idle connections
- Connection lifetime management
- Automatic connection recycling

### Caching Strategy

- Session data cached with TTL
- Activity tracking with buffered updates
- Efficient key naming conventions

## Monitoring and Debugging

### Logging

Comprehensive logging for:

- Session creation/deletion events
- Redis connection status
- Rate limiting events
- Token blacklisting operations

### Metrics

Available through Redis client:

- Connection pool statistics
- Operation latencies
- Error rates

## Development and Testing

### Local Development

For local development without Redis:

1. Set `REDIS_ENABLED=false` in `.env`
2. Application will use fallback implementations
3. Session management will be disabled

### Testing

Run the integration tests:

```bash
go test ./pkg/redis/... -v
go test ./pkg/cache/... -v
go test ./pkg/ratelimit/... -v
```

### Docker Development

Use the provided docker-compose files:

```bash
docker-compose -f docker-compose.dev.yml up
```

## Migration Guide

### From In-Memory to Redis

1. Update environment variables
2. Restart application
3. Sessions will automatically start using Redis
4. Rate limiting becomes distributed

### Configuration Changes

No code changes required - only environment variable updates needed.

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**

   - Check Redis URL and credentials
   - Verify network connectivity
   - Check Redis server status

2. **Session Not Found**

   - Sessions may have expired
   - Check session expiration settings
   - Verify session ID format

3. **Rate Limiting Not Working**
   - Verify Redis connection
   - Check rate limit configuration
   - Monitor Redis key patterns

### Debug Commands

```bash
# Check Redis connectivity
redis-cli -h your-host -p your-port ping

# Monitor Redis operations
redis-cli -h your-host -p your-port monitor

# Check session keys
redis-cli -h your-host -p your-port keys "session:*"
```

## Future Enhancements

Planned improvements:

- Session analytics dashboard
- Advanced rate limiting strategies
- Session persistence across restarts
- Multi-region session synchronization
- Session event webhooks
