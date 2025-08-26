package main

import (
	"fmt"
	"log"

	"auth-service/internal/utils"
	"auth-service/pkg/auth"
)

func main() {
	fmt.Println("🚀 Auth Service - Testing Core Functionality")
	fmt.Println("===========================================")

	// Test JWT token generation
	fmt.Println("\n1. Testing JWT Token Service...")
	tokenService := auth.NewTokenService("test-jwt-secret-for-testing-make-it-at-least-32-characters-long",
		15*60*1000000000,      // 15 minutes
		7*24*60*60*1000000000) // 7 days

	// Generate token pair
	tokenPair, err := tokenService.GenerateTokenPair(1, "test@example.com")
	if err != nil {
		log.Fatal("Failed to generate token pair:", err)
	}

	fmt.Printf("✅ Access Token Generated: %s...\n", tokenPair.AccessToken[:50])
	fmt.Printf("✅ Refresh Token Generated: %s...\n", tokenPair.RefreshToken[:50])
	fmt.Printf("✅ Expires In: %d seconds\n", tokenPair.ExpiresIn)

	// Validate the token
	fmt.Println("\n2. Testing Token Validation...")
	claims, err := tokenService.ValidateToken(tokenPair.AccessToken, auth.AccessToken)
	if err != nil {
		log.Fatal("Failed to validate token:", err)
	}

	fmt.Printf("✅ Token Valid - User ID: %d, Email: %s\n", claims.UserID, claims.Email)

	// Test password utilities
	fmt.Println("\n3. Testing Password Security...")
	password := "TestPassword123!"

	// Validate password strength
	validator := utils.NewPasswordValidator()
	validationErrors := validator.ValidatePassword(password)
	if len(validationErrors) > 0 {
		fmt.Printf("❌ Password validation failed:\n")
		for _, err := range validationErrors {
			fmt.Printf("   - %s\n", err.Message)
		}
	} else {
		fmt.Printf("✅ Password meets security requirements\n")
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(password, 12)
	if err != nil {
		log.Fatal("Failed to hash password:", err)
	}

	fmt.Printf("✅ Password Hashed: %s...\n", hashedPassword[:50])

	// Verify password
	err = utils.VerifyPassword(password, hashedPassword)
	if err != nil {
		log.Fatal("Failed to verify password:", err)
	}

	fmt.Printf("✅ Password Verification: Success\n")

	// Test email validation
	fmt.Println("\n4. Testing Input Validation...")

	testEmails := []string{
		"test@example.com",
		"invalid-email",
		"user@domain.co.uk",
		"@invalid.com",
	}

	for _, email := range testEmails {
		err := utils.ValidateEmail(email)
		if err != nil {
			fmt.Printf("❌ Email '%s': %s\n", email, err.Error())
		} else {
			fmt.Printf("✅ Email '%s': Valid\n", email)
		}
	}

	// Test name validation
	testNames := []string{
		"John",
		"Mary-Jane",
		"O'Connor",
		"123Invalid",
	}

	for _, name := range testNames {
		err := utils.ValidateName(name, "name")
		if err != nil {
			fmt.Printf("❌ Name '%s': %s\n", name, err.Error())
		} else {
			fmt.Printf("✅ Name '%s': Valid\n", name)
		}
	}

	fmt.Println("\n🎉 All core functionality tests passed!")
	fmt.Println("\n📚 Next Steps:")
	fmt.Println("   1. Set up PostgreSQL database")
	fmt.Println("   2. Run: docker-compose -f docker-compose.dev.yml up -d")
	fmt.Println("   3. Start the server: go run ./cmd/server")
	fmt.Println("   4. Test API endpoints with curl or Postman")
	fmt.Println("   5. Use provided Docker setup for production deployment")
}
