package handlers

import (
	"net/http"
	"time"

	"auth-service/internal/database"
	"auth-service/pkg/redis"

	"github.com/gin-gonic/gin"
)

// HealthHandler handles health check requests
type HealthHandler struct {
	db          *database.DB
	redisClient *redis.Client
	startTime   time.Time
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(db *database.DB, redisClient *redis.Client) *HealthHandler {
	return &HealthHandler{
		db:          db,
		redisClient: redisClient,
		startTime:   time.Now(),
	}
}

// HealthStatus represents the health status response
type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Uptime    string            `json:"uptime"`
	Checks    map[string]string `json:"checks"`
}

// Health handles basic health check requests
func (h *HealthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now(),
		"uptime":    time.Since(h.startTime).String(),
	})
}

// Ready handles readiness probe requests (includes database and Redis connectivity)
func (h *HealthHandler) Ready(c *gin.Context) {
	status := HealthStatus{
		Status:    "ok",
		Timestamp: time.Now(),
		Uptime:    time.Since(h.startTime).String(),
		Checks:    make(map[string]string),
	}

	// Check database connectivity
	if err := h.db.HealthCheck(); err != nil {
		status.Status = "error"
		status.Checks["database"] = "failed: " + err.Error()
		c.JSON(http.StatusServiceUnavailable, status)
		return
	}
	status.Checks["database"] = "ok"

	// Check Redis connectivity (if Redis client is available)
	if h.redisClient != nil {
		if err := h.redisClient.HealthCheck(); err != nil {
			status.Status = "error"
			status.Checks["redis"] = "failed: " + err.Error()
			c.JSON(http.StatusServiceUnavailable, status)
			return
		}
		status.Checks["redis"] = "ok"
	} else {
		status.Checks["redis"] = "disabled"
	}

	c.JSON(http.StatusOK, status)
}
