package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// GenerateRandomBytes returns securely generated random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded random string
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compares a password with a hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateUUID generates a new UUID
func GenerateUUID() string {
	return uuid.New().String()
}

// VerifyPKCEChallenge verifies the PKCE code challenge with the code verifier
func VerifyPKCEChallenge(codeVerifier, codeChallenge, method string) bool {
	switch method {
	case "S256":
		// SHA-256 challenge
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		expectedChallenge := base64.URLEncoding.EncodeToString(h.Sum(nil))
		// Remove padding
		expectedChallenge = strings.TrimRight(expectedChallenge, "=")
		return expectedChallenge == codeChallenge
	case "plain":
		// Plain challenge
		return codeVerifier == codeChallenge
	default:
		// Unsupported method
		return false
	}
}

// BuildRedirectURI builds a URI with query parameters
func BuildRedirectURI(baseURI string, params map[string]string) (string, error) {
	parsedURL, err := url.Parse(baseURI)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	for key, value := range params {
		query.Set(key, value)
	}
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// ErrorResponse sends a standardized error response
func ErrorResponse(c *fiber.Ctx, status int, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"error": message,
	})
}

// SuccessResponse sends a standardized success response
func SuccessResponse(c *fiber.Ctx, data interface{}) error {
	return c.JSON(data)
}

// ParseScopes parses a space-separated string of scopes to a slice
func ParseScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}
	return strings.Split(scopeString, " ")
}

// JoinScopes joins a slice of scopes to a space-separated string
func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// PrettyPrintJSON returns a prettified JSON string
func PrettyPrintJSON(data interface{}) string {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// ComputeS256Challenge computes a PKCE S256 challenge from a verifier
func ComputeS256Challenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
	return challenge
}

// HashString returns a hex-encoded SHA-256 hash of a string
func HashString(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// Contains checks if a slice contains a given string
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ParseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func ParseBasicAuth(auth string) (username, password string, ok bool) {
	if auth == "" {
		return "", "", false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return "", "", false
	}

	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}

	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return "", "", false
	}

	return cs[:s], cs[s+1:], true
} 