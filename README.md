# Authentication Service

A production-ready, scalable authentication service built with Go, featuring JWT-based authentication, PostgreSQL database, Docker containerization, and comprehensive CI/CD pipelines.

## Features

- 🔐 **Secure Authentication**: JWT-based authentication with access and refresh tokens
- 👥 **User Management**: Registration, login, profile management
- 🔒 **Password Security**: Bcrypt hashing, strength validation, reset functionality
- 🛡️ **Security**: Rate limiting, account locking, CORS, security headers
- 🗄️ **Database**: PostgreSQL with proper migrations and connection pooling
- 🐳 **Containerization**: Docker and Docker Compose for easy deployment
- ⚡ **Performance**: Optimized with proper caching and connection pooling
- 📊 **Observability**: Structured logging, health checks, metrics endpoints
- 🧪 **Testing**: Comprehensive unit and integration tests
- 🚀 **CI/CD**: Automated testing, security scanning, and deployment

## Architecture

```
├── cmd/server/          # Application entry point
├── internal/            # Private application code
│   ├── config/         # Configuration management
│   ├── database/       # Database connection and migrations
│   ├── handlers/       # HTTP request handlers
│   ├── middleware/     # HTTP middleware (auth, logging, etc.)
│   ├── models/         # Data models and DTOs
│   ├── repository/     # Data access layer
│   ├── services/       # Business logic layer
│   └── utils/          # Utility functions
├── pkg/                # Public packages
│   ├── auth/          # JWT token management
│   ├── errors/        # Error handling
│   └── logger/        # Structured logging
├── migrations/         # Database migrations
├── scripts/           # Utility scripts
└── .github/workflows/ # CI/CD pipelines
```

## Quick Start

### Prerequisites

- Go 1.21+
- Docker and Docker Compose
- PostgreSQL (if running locally)

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd auth-service
```

### 2. Environment Setup

Copy the environment template and configure:

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Start Development Environment

```bash
# Start PostgreSQL and Redis
make setup-dev

# Run the application
make run
```

### 4. Using Docker Compose

```bash
# Build and start all services
docker-compose up --build

# Or for development (database only)
docker-compose -f docker-compose.dev.yml up -d
```

## API Documentation

### Base URL

```
http://localhost:8080/api/v1
```

### Authentication Endpoints

#### Register User

```http
POST /auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "StrongPassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**

```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "is_verified": false,
      "created_at": "2024-01-15T10:30:00Z"
    },
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_in": 900
  }
}
```

#### Sign In

```http
POST /auth/signin
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "StrongPassword123!"
}
```

#### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### Forgot Password

```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Reset Password

```http
POST /auth/reset-password
Content-Type: application/json

{
  "token": "reset-token-from-email",
  "password": "NewStrongPassword123!"
}
```

### Protected Endpoints

All protected endpoints require the `Authorization` header:

```http
Authorization: Bearer <access_token>
```

#### Get Profile

```http
GET /profile
Authorization: Bearer <access_token>
```

#### Update Profile

```http
PUT /profile
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "first_name": "Jane",
  "last_name": "Smith"
}
```

#### Change Password

```http
POST /change-password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "current_password": "OldPassword123!",
  "new_password": "NewPassword123!"
}
```

### Health Check Endpoints

```http
GET /health          # Basic health check
GET /ready           # Readiness check (includes DB)
```

## Configuration

### Environment Variables

| Variable                | Description                                  | Default          |
| ----------------------- | -------------------------------------------- | ---------------- |
| `PORT`                  | Server port                                  | `8080`           |
| `ENV`                   | Environment (development/staging/production) | `development`    |
| `DATABASE_URL`          | PostgreSQL connection string                 | `postgres://...` |
| `JWT_SECRET`            | JWT signing secret (min 32 chars)            | Required         |
| `JWT_ACCESS_EXPIRY`     | Access token expiry                          | `15m`            |
| `JWT_REFRESH_EXPIRY`    | Refresh token expiry                         | `168h`           |
| `BCRYPT_COST`           | Bcrypt hashing cost (10-15)                  | `12`             |
| `MAX_LOGIN_ATTEMPTS`    | Max failed login attempts                    | `5`              |
| `ACCOUNT_LOCK_DURATION` | Account lock duration                        | `15m`            |
| `RATE_LIMIT_RPS`        | Rate limit requests per second               | `10`             |

### Security Configuration

- **Password Requirements**: Minimum 8 characters, uppercase, lowercase, number, special character
- **JWT Tokens**: HS256 algorithm, configurable expiry
- **Rate Limiting**: Configurable per-IP rate limiting
- **Account Security**: Automatic locking after failed attempts
- **CORS**: Configurable allowed origins

## Development

### Available Make Commands

```bash
make help              # Show all available commands
make build             # Build the application
make test              # Run unit tests
make test-coverage     # Run tests with coverage
make lint              # Run linters
make security-check    # Run security checks
make docker-build      # Build Docker image
make setup-dev         # Setup development environment
make ci                # Run full CI pipeline locally
```

### Running Tests

```bash
# Unit tests
make test

# With coverage
make test-coverage

# Integration tests (requires running services)
make setup-dev
go test -tags=integration ./...
```

### Code Quality

The project uses several tools for maintaining code quality:

- **golangci-lint**: Comprehensive linter
- **gosec**: Security scanner
- **go vet**: Go's built-in checker
- **gofmt**: Code formatting

## Deployment

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up --build

# Production deployment
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

```yaml
# Example Kubernetes deployment (customize as needed)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
        - name: auth-service
          image: ghcr.io/yourusername/auth-service:latest
          ports:
            - containerPort: 8080
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: auth-service-secrets
                  key: database-url
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: auth-service-secrets
                  key: jwt-secret
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
```

## Monitoring and Observability

### Health Checks

- `/health`: Basic application health
- `/ready`: Readiness including database connectivity

### Logging

Structured JSON logging with configurable levels:

```json
{
  "time": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "msg": "Request processed",
  "method": "POST",
  "path": "/api/v1/auth/signin",
  "status": 200,
  "latency": "45ms",
  "ip": "192.168.1.1"
}
```

### Metrics

Consider integrating with:

- Prometheus for metrics collection
- Grafana for visualization
- Jaeger for distributed tracing

## Security Considerations

### Production Checklist

- [ ] Change default JWT secret
- [ ] Use strong database passwords
- [ ] Enable HTTPS/TLS
- [ ] Configure proper CORS origins
- [ ] Set up proper firewall rules
- [ ] Enable audit logging
- [ ] Regular security updates
- [ ] Implement rate limiting
- [ ] Use secrets management

### Security Headers

The service automatically adds security headers:

- `X-XSS-Protection`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Strict-Transport-Security`
- `Content-Security-Policy`

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices and idioms
- Write comprehensive tests for new features
- Update documentation for API changes
- Ensure all CI checks pass
- Use conventional commit messages

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- Create an issue in the GitHub repository
- Check the [FAQ](docs/FAQ.md)
- Review the [troubleshooting guide](docs/TROUBLESHOOTING.md)

## Roadmap

- [ ] Email verification system
- [ ] OAuth2 integration (Google, GitHub, etc.)
- [ ] Two-factor authentication (2FA)
- [ ] Role-based access control (RBAC)
- [ ] API key management
- [ ] Advanced rate limiting with Redis
- [ ] Audit logging
- [ ] Session management
- [ ] Password policy enforcement
- [ ] Multi-tenant support
