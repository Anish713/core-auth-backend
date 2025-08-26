package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenType represents different types of JWT tokens
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// Claims represents the JWT claims
type Claims struct {
	UserID    int64     `json:"user_id"`
	Email     string    `json:"email"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// TokenService handles JWT token operations
type TokenService struct {
	secret        []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// NewTokenService creates a new token service
func NewTokenService(secret string, accessExpiry, refreshExpiry time.Duration) *TokenService {
	return &TokenService{
		secret:        []byte(secret),
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}
}

// GenerateTokenPair generates both access and refresh tokens
func (ts *TokenService) GenerateTokenPair(userID int64, email string) (*TokenPair, error) {
	now := time.Now()

	// Generate access token
	accessToken, err := ts.generateToken(userID, email, AccessToken, now.Add(ts.accessExpiry))
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := ts.generateToken(userID, email, RefreshToken, now.Add(ts.refreshExpiry))
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(ts.accessExpiry.Seconds()),
		ExpiresAt:    now.Add(ts.accessExpiry),
	}, nil
}

// generateToken generates a JWT token with the specified claims
func (ts *TokenService) generateToken(userID int64, email string, tokenType TokenType, expiresAt time.Time) (string, error) {
	now := time.Now()

	claims := &Claims{
		UserID:    userID,
		Email:     email,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "auth-service",
			Subject:   fmt.Sprintf("%d", userID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(ts.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func (ts *TokenService) ValidateToken(tokenString string, expectedType TokenType) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ts.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify token type
	if claims.TokenType != expectedType {
		return nil, fmt.Errorf("invalid token type: expected %s, got %s", expectedType, claims.TokenType)
	}

	// Check if token is expired
	if time.Now().After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("token has expired")
	}

	return claims, nil
}

// RefreshAccessToken generates a new access token using a valid refresh token
func (ts *TokenService) RefreshAccessToken(refreshTokenString string) (*TokenPair, error) {
	// Validate the refresh token
	claims, err := ts.ValidateToken(refreshTokenString, RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Generate new token pair
	tokenPair, err := ts.GenerateTokenPair(claims.UserID, claims.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new token pair: %w", err)
	}

	return tokenPair, nil
}

// ExtractUserID extracts the user ID from a valid access token
func (ts *TokenService) ExtractUserID(tokenString string) (int64, error) {
	claims, err := ts.ValidateToken(tokenString, AccessToken)
	if err != nil {
		return 0, err
	}

	return claims.UserID, nil
}

// ExtractUserEmail extracts the user email from a valid access token
func (ts *TokenService) ExtractUserEmail(tokenString string) (string, error) {
	claims, err := ts.ValidateToken(tokenString, AccessToken)
	if err != nil {
		return "", err
	}

	return claims.Email, nil
}
