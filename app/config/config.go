package config

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"time"
)

// Config holds application configuration
type Config struct {
	Port               string
	JWTPrivateKey      *rsa.PrivateKey
	JWTPublicKey       *rsa.PublicKey
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	AdminUsername      string
	AdminPassword      string
}

// NewConfig creates a new Config with default or environment values
func NewConfig() *Config {
	// Generate RSA keys for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	adminUsername := os.Getenv("ADMIN_USERNAME")
	if adminUsername == "" {
		adminUsername = "admin"
	}

	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "admin123" // In production, this should be a strong, randomly generated password
	}

	return &Config{
		Port:               port,
		JWTPrivateKey:      privateKey,
		JWTPublicKey:       &privateKey.PublicKey,
		AccessTokenExpiry:  time.Hour,     // 1 hour
		RefreshTokenExpiry: time.Hour * 24, // 24 hours
		AdminUsername:      adminUsername,
		AdminPassword:      adminPassword,
	}
} 