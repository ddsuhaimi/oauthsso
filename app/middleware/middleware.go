package middleware

import (
	"sync"
	"time"

	"github.com/dedisuhaimi/oauthsso/app/config"
	"github.com/dedisuhaimi/oauthsso/app/models"
	"github.com/dedisuhaimi/oauthsso/app/utils"
	"github.com/gofiber/fiber/v2"
)

// Admin authentication middleware
func AdminAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get username and password from Basic Auth
		auth := c.Get("Authorization")
		username, password, ok := utils.ParseBasicAuth(auth)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Basic authentication required",
			})
		}

		// Get config from app locals
		cfg := c.Locals("config").(*config.Config)
		if username != cfg.AdminUsername || password != cfg.AdminPassword {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid credentials",
			})
		}

		return c.Next()
	}
}

// ValidateToken middleware validates a JWT token
func ValidateToken(jwtService *models.JWTService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization header is required",
			})
		}

		// Extract the token
		tokenString, err := models.ExtractTokenFromHeader(authHeader)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Validate the token
		claims, err := jwtService.ValidateToken(tokenString)
		if err != nil {
			status := fiber.StatusUnauthorized
			if err == models.ErrExpiredToken {
				status = fiber.StatusUnauthorized
			}
			return c.Status(status).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Store claims in context for handlers to use
		c.Locals("claims", claims)
		return c.Next()
	}
}

// CSRFProtection middleware helps protect against CSRF attacks for the OAuth authorize endpoint
func CSRFProtection() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// For GET requests, generate and store a CSRF token
		if c.Method() == "GET" {
			// Generate a CSRF token
			csrfToken, err := utils.GenerateRandomString(32)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to generate CSRF token",
				})
			}

			// Store the token in the session (in a production app, this would be in a cookie or server-side session)
			c.Cookie(&fiber.Cookie{
				Name:     "csrf_token",
				Value:    csrfToken,
				HTTPOnly: true,
				Secure:   true,
				SameSite: "lax",
			})

			// Add the token to the context for the template to use
			c.Locals("csrf_token", csrfToken)
		} else if c.Method() == "POST" {
			// For POST requests, verify the CSRF token
			csrfCookie := c.Cookies("csrf_token")
			csrfToken := c.FormValue("csrf_token")

			if csrfCookie == "" || csrfToken == "" || csrfCookie != csrfToken {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Invalid or missing CSRF token",
				})
			}
		}

		return c.Next()
	}
}

// Simple in-memory rate limiter
type rateLimiter struct {
	mu      sync.Mutex
	ipHits  map[string][]time.Time
	limit   int
	timeWindow time.Duration
}

// RateLimiter middleware limits request rates
func RateLimiter(limit int, timeWindowSeconds int) fiber.Handler {
	limiter := &rateLimiter{
		ipHits:     make(map[string][]time.Time),
		limit:      limit,
		timeWindow: time.Duration(timeWindowSeconds) * time.Second,
	}

	return func(c *fiber.Ctx) error {
		// Get client IP
		ip := c.IP()
		
		limiter.mu.Lock()
		defer limiter.mu.Unlock()

		// Remove old hits outside the time window
		now := time.Now()
		var validHits []time.Time
		
		for _, hit := range limiter.ipHits[ip] {
			if now.Sub(hit) <= limiter.timeWindow {
				validHits = append(validHits, hit)
			}
		}
		limiter.ipHits[ip] = validHits

		// Check if we've exceeded the rate limit
		if len(validHits) >= limiter.limit {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Rate limit exceeded",
			})
		}

		// Add current hit
		limiter.ipHits[ip] = append(limiter.ipHits[ip], now)

		return c.Next()
	}
}

// ClientAuthentication middleware authenticates OAuth clients
func ClientAuthentication(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get client credentials from Basic Auth
		auth := c.Get("Authorization")
		clientID, clientSecret, ok := utils.ParseBasicAuth(auth)
		
		if !ok {
			// If not in basic auth, try form params (for public clients)
			clientID = c.FormValue("client_id")
			clientSecret = c.FormValue("client_secret")
			
			if clientID == "" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Client authentication required",
				})
			}
		}

		// Verify client exists
		client, err := store.GetClientByID(clientID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid client",
			})
		}

		// For confidential clients, verify the secret
		// Public clients might not have a secret (like SPAs)
		if client.Secret != "" && !utils.CheckPasswordHash(clientSecret, client.Secret) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid client credentials",
			})
		}

		// Store client in context for handlers to use
		c.Locals("client", client)
		return c.Next()
	}
} 