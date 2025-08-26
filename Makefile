# Makefile for auth-service

.PHONY: help build test clean run docker-build docker-run docker-stop setup-dev migration-up migration-down lint security-check

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=auth-service
BINARY_PATH=./cmd/server

# Build the application
build: ## Build the application
	$(GOBUILD) -o $(BINARY_NAME) $(BINARY_PATH)

# Build for production
build-prod: ## Build for production with optimizations
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) \
		-ldflags='-w -s -extldflags "-static"' \
		-a -installsuffix cgo \
		-o $(BINARY_NAME) $(BINARY_PATH)

# Run tests
test: ## Run unit tests
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run tests with coverage report
test-coverage: ## Run tests with coverage report
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
benchmark: ## Run benchmark tests
	$(GOTEST) -bench=. -benchmem ./...

# Clean build artifacts
clean: ## Clean build artifacts
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

# Run the application
run: ## Run the application locally
	$(GOCMD) run $(BINARY_PATH)

# Install dependencies
deps: ## Install/update dependencies
	$(GOMOD) download
	$(GOMOD) tidy

# Lint the code
lint: ## Run linters
	golangci-lint run ./...

# Security check
security-check: ## Run security checks
	gosec ./...

# Format code
fmt: ## Format Go code
	$(GOCMD) fmt ./...

# Vet code
vet: ## Run go vet
	$(GOCMD) vet ./...

# Generate code
generate: ## Run go generate
	$(GOCMD) generate ./...

# Docker commands
docker-build: ## Build Docker image
	docker build -t auth-service:latest .

docker-run: ## Run application in Docker
	docker-compose up -d

docker-stop: ## Stop Docker containers
	docker-compose down

docker-logs: ## Show Docker logs
	docker-compose logs -f auth-service

# Development environment setup
setup-dev: ## Setup development environment
	docker-compose -f docker-compose.dev.yml up -d
	@echo "Development environment is ready!"
	@echo "PostgreSQL: localhost:5432 (user: postgres, password: password)"
	@echo "Redis: localhost:6379"

teardown-dev: ## Teardown development environment
	docker-compose -f docker-compose.dev.yml down -v

# Database migrations (when implemented)
migrate-up: ## Run database migrations up
	@echo "Running migrations up..."
	# Add actual migration command here

migrate-down: ## Run database migrations down
	@echo "Running migrations down..."
	# Add actual migration command here

migrate-create: ## Create a new migration file
	@echo "Creating new migration..."
	# Add migration creation command here

# Database operations
db-reset: ## Reset database (development only)
	docker-compose -f docker-compose.dev.yml down postgres
	docker volume rm learn_postgres_data_dev || true
	docker-compose -f docker-compose.dev.yml up -d postgres
	sleep 10
	@echo "Database reset complete"

# Load testing
load-test: ## Run load tests
	@echo "Running load tests..."
	# Add load testing commands (e.g., with k6)

# API testing
api-test: ## Run API tests
	@echo "Running API tests..."
	# Add API testing commands (e.g., with Newman/Postman)

# Code quality checks
quality: lint vet security-check ## Run all code quality checks

# Full CI pipeline locally
ci: clean deps quality test build ## Run full CI pipeline locally

# Release preparation
release-prep: ci test-coverage ## Prepare for release

# Install development tools
install-tools: ## Install development tools
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOGET) github.com/securecodewarrior/github-action-gosec/cmd/gosec@latest

# Show project status
status: ## Show project status
	@echo "=== Project Status ==="
	@echo "Go version: $$(go version)"
	@echo "Dependencies:"
	@$(GOMOD) list -m all
	@echo "Build status:"
	@if [ -f $(BINARY_NAME) ]; then echo "✓ Binary exists"; else echo "✗ Binary not built"; fi
	@echo "Docker status:"
	@docker-compose ps 2>/dev/null || echo "Docker compose not running"