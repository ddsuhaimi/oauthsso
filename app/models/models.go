package models

import (
	"time"
)

// User represents a registered user
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	HashedPassword string    `json:"-"` // Never expose in JSON
	Status       string    `json:"status"` // "active", "pending", "disabled"
	CreatedAt    time.Time `json:"created_at"`
}

// Client represents an OAuth client application
type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"-"` // Never expose in JSON
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
}

// AuthCode represents an OAuth authorization code
type AuthCode struct {
	Code           string    `json:"code"`
	UserID         string    `json:"user_id"`
	ClientID       string    `json:"client_id"`
	RedirectURI    string    `json:"redirect_uri"`
	Scopes         []string  `json:"scopes"`
	PKCEChallenge  string    `json:"pkce_challenge,omitempty"`
	PKCEMethod     string    `json:"pkce_method,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
}

// Token represents an OAuth token pair (access + refresh)
type Token struct {
	AccessJTI     string    `json:"access_jti"`
	RefreshJTI    string    `json:"refresh_jti,omitempty"`
	UserID        string    `json:"user_id"`
	ClientID      string    `json:"client_id"`
	Scopes        []string  `json:"scopes"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// TokenResponse is what is returned to the client during token exchange
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// IntrospectResponse is the response format for token introspection
type IntrospectResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Jti       string   `json:"jti,omitempty"`
}

// Claims represents the JWT claims structure
type Claims struct {
	Sub       string   `json:"sub"`        // User ID
	Jti       string   `json:"jti"`        // Token ID
	ClientID  string   `json:"client_id"`  // Client ID
	Scope     []string `json:"scope"`      // Scopes
	Email     string   `json:"email,omitempty"`     // User email (if scope allows)
} 