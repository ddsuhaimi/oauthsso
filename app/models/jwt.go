package models

import (
	"errors"
	"strings"
	"time"

	"github.com/dedisuhaimi/oauthsso/app/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrMalformedToken   = errors.New("malformed token")
)

// JWTService handles JWT token generation and validation
type JWTService struct {
	config *config.Config
}

// NewJWTService creates a new JWT service
func NewJWTService(config *config.Config) *JWTService {
	return &JWTService{
		config: config,
	}
}

// GenerateAccessToken creates a new JWT access token
func (s *JWTService) GenerateAccessToken(userID, clientID string, email string, scopes []string) (string, string, error) {
	// Generate a unique JTI (JWT ID)
	jti := uuid.New().String()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID,                                // Subject: User ID
		"jti": jti,                                   // JWT ID: Unique identifier for this token
		"iat": now.Unix(),                            // Issued At: Time when the token was generated
		"exp": now.Add(s.config.AccessTokenExpiry).Unix(), // Expiration Time: Time after which the token expires
		"client_id": clientID,                        // OAuth 2.0 client ID
		"scope": scopes,                              // OAuth 2.0 scopes
	}

	// Add email only if "email" is in the requested scopes
	if contains(scopes, "email") {
		claims["email"] = email
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(s.config.JWTPrivateKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

// GenerateRefreshToken creates a new JWT refresh token
func (s *JWTService) GenerateRefreshToken(userID, clientID string) (string, string, error) {
	// Generate a unique JTI (JWT ID)
	jti := uuid.New().String()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID,                                 // Subject: User ID
		"jti": jti,                                    // JWT ID: Unique identifier for this token
		"iat": now.Unix(),                             // Issued At: Time when the token was generated
		"exp": now.Add(s.config.RefreshTokenExpiry).Unix(), // Expiration Time: Time after which the token expires
		"client_id": clientID,                         // OAuth 2.0 client ID
		"token_type": "refresh",                       // Indicate this is a refresh token
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(s.config.JWTPrivateKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

// ValidateToken validates a JWT token and returns its claims
func (s *JWTService) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidSignature
		}
		return s.config.JWTPublicKey, nil
	})

	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	// Validate token is properly formed
	if !token.Valid {
		return nil, ErrMalformedToken
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrMalformedToken
	}

	return claims, nil
}

// ExtractTokenFromHeader extracts the JWT token from the Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	parts := strings.Split(authHeader, "Bearer ")
	if len(parts) != 2 {
		return "", errors.New("authorization header format must be Bearer {token}")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("token not found in authorization header")
	}

	return token, nil
}

// Helper function to check if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
} 