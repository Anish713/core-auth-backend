package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/database"
	"auth-service/internal/handlers"
	"auth-service/internal/middleware"
	"auth-service/internal/repository"
	"auth-service/internal/services"
	"auth-service/pkg/cache"
	"auth-service/pkg/logger"
	"auth-service/pkg/ratelimit"
	"auth-service/pkg/redis"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	_ = godotenv.Load()

	// Initialize logger
	log := logger.New()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration", "error", err)
	}

	// Connect to database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database", "error", err)
	}
	defer db.Close()

	// Run migrations
	if err := database.Migrate(db); err != nil {
		log.Fatal("Failed to run migrations", "error", err)
	}

	// Initialize Redis client (optional, fallback to in-memory if Redis is disabled)
	var redisClient *redis.Client
	var cacheService cache.CacheService
	var sessionService cache.SessionService
	var rateLimiter ratelimit.RateLimiter

	if cfg.RedisEnabled {
		redisConfig := &redis.Config{
			URL:      cfg.RedisURL,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		}

		redisClient, err = redis.NewClient(redisConfig)
		if err != nil {
			log.Error("Failed to connect to Redis, falling back to in-memory cache", "error", err)
			// Could implement in-memory fallbacks here
			redisClient = nil
		} else {
			log.Info("Connected to Redis successfully")
			cacheService = cache.NewRedisCache(redisClient)
			sessionService = cache.NewRedisSessionService(redisClient)

			// Initialize Redis-based rate limiter
			rateLimitConfig := &ratelimit.Config{
				Limit:      cfg.RateLimitRPS,
				Window:     time.Minute,
				Identifier: "api",
			}
			rateLimiter = ratelimit.NewRedisRateLimiter(redisClient, rateLimitConfig)
		}
	}

	// Ensure Redis client is closed on shutdown
	if redisClient != nil {
		defer redisClient.Close()
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)

	// Initialize services
	authService := services.NewAuthService(userRepo, cfg.JWTSecret)

	// Initialize session manager if Redis is available
	var sessionManager services.SessionManager
	if sessionService != nil && cacheService != nil {
		sessionManagerConfig := &services.SessionManagerConfig{
			DefaultTTL:  cfg.JWTAccessExpiry,
			MaxSessions: 5, // Maximum sessions per user
		}
		sessionManager = services.NewSessionManager(sessionService, cacheService, sessionManagerConfig)
		log.Info("Session manager initialized")
	} else {
		log.Warn("Session manager not available - Redis not enabled or failed to connect")
	}

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, sessionManager, log)
	healthHandler := handlers.NewHealthHandler(db, redisClient)

	// Setup router
	router := setupRouter(cfg, authHandler, healthHandler, rateLimiter, log)

	// Create HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Starting server", "port", cfg.Port, "env", cfg.Environment)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown", "error", err)
	}

	log.Info("Server exited")
}

func setupRouter(cfg *config.Config, authHandler *handlers.AuthHandler, healthHandler *handlers.HealthHandler, rateLimiter ratelimit.RateLimiter, log logger.Logger) *gin.Engine {
	// Set gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Add middleware
	router.Use(middleware.Logger(log))
	router.Use(middleware.Recovery(log))
	router.Use(middleware.CORS())
	router.Use(middleware.SecurityHeaders())

	// Add rate limiting middleware if rate limiter is available
	if cfg.RateLimitEnabled && rateLimiter != nil {
		router.Use(middleware.RateLimit(rateLimiter))
	}

	// Health check endpoints
	router.GET("/health", healthHandler.Health)
	router.GET("/ready", healthHandler.Ready)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/signup", authHandler.SignUp)
			auth.POST("/signin", authHandler.SignIn)
			auth.POST("/forgot-password", authHandler.ForgotPassword)
			auth.POST("/reset-password", authHandler.ResetPassword)
			auth.POST("/refresh", authHandler.RefreshToken)
		}

		// Protected routes
		protected := v1.Group("/")
		protected.Use(middleware.AuthRequired(cfg.JWTSecret))
		{
			protected.GET("/profile", authHandler.GetProfile)
			protected.PUT("/profile", authHandler.UpdateProfile)
			protected.POST("/change-password", authHandler.ChangePassword)

			// Authentication endpoints
			protected.POST("/auth/signout", authHandler.SignOut)

			// Session management endpoints
			protected.GET("/sessions", authHandler.GetActiveSessions)
			protected.DELETE("/sessions/:sessionId", authHandler.TerminateSession)
			protected.DELETE("/sessions", authHandler.TerminateAllSessions)
		}
	}

	return router
}
