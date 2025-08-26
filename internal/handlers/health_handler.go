package handlers

import (
	"net/http"
	"time"

	"auth-service/internal/database"

	"github.com/gin-gonic/gin"
)

// HealthHandler handles health check requests
type HealthHandler struct {
	db        *database.DB
	startTime time.Time
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(db *database.DB) *HealthHandler {
	return &HealthHandler{
		db:        db,
		startTime: time.Now(),
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

// Ready handles readiness probe requests (includes database connectivity)
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
	c.JSON(http.StatusOK, status)
}
