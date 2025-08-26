package repository

import (
	"database/sql"
	"fmt"
	"time"

	"auth-service/internal/database"
	"auth-service/internal/models"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// User operations
	Create(user *models.User) error
	GetByID(id int64) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	Update(user *models.User) error
	UpdateLastLogin(userID int64) error

	// Account security operations
	UpdateFailedLoginAttempts(userID int64, attempts int) error
	LockAccount(userID int64, until time.Time) error
	UnlockAccount(userID int64) error

	// Password reset operations
	CreatePasswordReset(reset *models.PasswordReset) error
	GetPasswordReset(token string) (*models.PasswordReset, error)
	MarkPasswordResetUsed(token string) error
	CleanupExpiredPasswordResets() error

	// Login attempt tracking
	RecordLoginAttempt(attempt *models.LoginAttempt) error
	GetFailedLoginAttemptsCount(email string, since time.Time) (int, error)
}

// userRepository implements UserRepository
type userRepository struct {
	db *database.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *database.DB) UserRepository {
	return &userRepository{db: db}
}

// Create creates a new user
func (r *userRepository) Create(user *models.User) error {
	query := `
		INSERT INTO users (email, password_hash, first_name, last_name, is_verified, is_active)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`

	err := r.db.QueryRow(
		query,
		user.Email,
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.IsVerified,
		user.IsActive,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(id int64) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, email, password_hash, first_name, last_name, is_verified, is_active,
			   failed_login_attempts, locked_until, last_login, created_at, updated_at
		FROM users
		WHERE id = $1 AND is_active = true`

	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsVerified,
		&user.IsActive,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(email string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, email, password_hash, first_name, last_name, is_verified, is_active,
			   failed_login_attempts, locked_until, last_login, created_at, updated_at
		FROM users
		WHERE email = $1 AND is_active = true`

	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsVerified,
		&user.IsActive,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

// Update updates a user
func (r *userRepository) Update(user *models.User) error {
	query := `
		UPDATE users 
		SET first_name = $1, last_name = $2, password_hash = $3, is_verified = $4, updated_at = CURRENT_TIMESTAMP
		WHERE id = $5`

	result, err := r.db.Exec(query, user.FirstName, user.LastName, user.PasswordHash, user.IsVerified, user.ID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdateLastLogin updates the user's last login time
func (r *userRepository) UpdateLastLogin(userID int64) error {
	query := `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1`

	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// UpdateFailedLoginAttempts updates the failed login attempts count
func (r *userRepository) UpdateFailedLoginAttempts(userID int64, attempts int) error {
	query := `UPDATE users SET failed_login_attempts = $1 WHERE id = $2`

	_, err := r.db.Exec(query, attempts, userID)
	if err != nil {
		return fmt.Errorf("failed to update failed login attempts: %w", err)
	}

	return nil
}

// LockAccount locks a user account until the specified time
func (r *userRepository) LockAccount(userID int64, until time.Time) error {
	query := `UPDATE users SET locked_until = $1 WHERE id = $2`

	_, err := r.db.Exec(query, until, userID)
	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	return nil
}

// UnlockAccount unlocks a user account
func (r *userRepository) UnlockAccount(userID int64) error {
	query := `UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = $1`

	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	return nil
}

// CreatePasswordReset creates a password reset record
func (r *userRepository) CreatePasswordReset(reset *models.PasswordReset) error {
	query := `
		INSERT INTO password_resets (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, created_at`

	err := r.db.QueryRow(
		query,
		reset.UserID,
		reset.Token,
		reset.ExpiresAt,
	).Scan(&reset.ID, &reset.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create password reset: %w", err)
	}

	return nil
}

// GetPasswordReset retrieves a password reset by token
func (r *userRepository) GetPasswordReset(token string) (*models.PasswordReset, error) {
	reset := &models.PasswordReset{}
	query := `
		SELECT id, user_id, token, expires_at, used, created_at
		FROM password_resets
		WHERE token = $1 AND used = false AND expires_at > CURRENT_TIMESTAMP`

	err := r.db.QueryRow(query, token).Scan(
		&reset.ID,
		&reset.UserID,
		&reset.Token,
		&reset.ExpiresAt,
		&reset.Used,
		&reset.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("password reset token not found or expired")
		}
		return nil, fmt.Errorf("failed to get password reset: %w", err)
	}

	return reset, nil
}

// MarkPasswordResetUsed marks a password reset as used
func (r *userRepository) MarkPasswordResetUsed(token string) error {
	query := `UPDATE password_resets SET used = true WHERE token = $1`

	_, err := r.db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to mark password reset as used: %w", err)
	}

	return nil
}

// CleanupExpiredPasswordResets removes expired password reset records
func (r *userRepository) CleanupExpiredPasswordResets() error {
	query := `DELETE FROM password_resets WHERE expires_at < CURRENT_TIMESTAMP`

	_, err := r.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired password resets: %w", err)
	}

	return nil
}

// RecordLoginAttempt records a login attempt
func (r *userRepository) RecordLoginAttempt(attempt *models.LoginAttempt) error {
	query := `
		INSERT INTO login_attempts (email, ip_address, user_agent, success)
		VALUES ($1, $2, $3, $4)`

	_, err := r.db.Exec(
		query,
		attempt.Email,
		attempt.IPAddress,
		attempt.UserAgent,
		attempt.Success,
	)

	if err != nil {
		return fmt.Errorf("failed to record login attempt: %w", err)
	}

	return nil
}

// GetFailedLoginAttemptsCount gets the count of failed login attempts for an email since a certain time
func (r *userRepository) GetFailedLoginAttemptsCount(email string, since time.Time) (int, error) {
	var count int
	query := `
		SELECT COUNT(*)
		FROM login_attempts
		WHERE email = $1 AND success = false AND attempted_at > $2`

	err := r.db.QueryRow(query, email, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get failed login attempts count: %w", err)
	}

	return count, nil
}
