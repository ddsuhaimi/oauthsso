package handlers

import (
	"time"

	"github.com/dedisuhaimi/oauthsso/app/models"
	"github.com/dedisuhaimi/oauthsso/app/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Authorize handles the OAuth 2.0 authorization endpoint
func Authorize(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get required parameters
		responseType := c.Query("response_type")
		clientID := c.Query("client_id")
		redirectURI := c.Query("redirect_uri")
		scope := c.Query("scope")
		state := c.Query("state")
		codeChallenge := c.Query("code_challenge")
		codeChallengeMethod := c.Query("code_challenge_method", "plain")

		// Validate response type (only 'code' supported for now)
		if responseType != "code" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "unsupported_response_type",
				"error_description": "Only 'code' response type is supported",
			})
		}

		// Validate client ID
		client, err := store.GetClientByID(clientID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_client",
				"error_description": "Client ID is invalid",
			})
		}

		// Validate redirect URI
		validRedirectURI := false
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				validRedirectURI = true
				break
			}
		}
		if !validRedirectURI {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_request",
				"error_description": "Redirect URI doesn't match registered URIs",
			})
		}

		// Parse requested scopes
		requestedScopes := utils.ParseScopes(scope)

		// Validate scopes
		validScopes := []string{}
		for _, requestedScope := range requestedScopes {
			for _, clientScope := range client.Scopes {
				if requestedScope == clientScope {
					validScopes = append(validScopes, requestedScope)
					break
				}
			}
		}

		// If this is a form submission, process login
		if c.Method() == "POST" {
			email := c.FormValue("email")
			password := c.FormValue("password")

			// Validate user credentials
			user, err := store.GetUserByEmail(email)
			if err != nil || !utils.CheckPasswordHash(password, user.HashedPassword) {
				// In a real application, you might want to increment a counter here
				// for brute-force protection
				return c.Status(fiber.StatusUnauthorized).Render("login", fiber.Map{
					"error": "Invalid email or password",
					"csrf_token": c.Locals("csrf_token"),
					"client_name": client.Name,
					"scopes": validScopes,
				})
			}

			// Generate an authorization code
			code, err := utils.GenerateRandomString(32)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "server_error",
					"error_description": "Failed to generate authorization code",
				})
			}

			// Store the authorization code
			authCode := &models.AuthCode{
				Code:           code,
				UserID:         user.ID,
				ClientID:       clientID,
				RedirectURI:    redirectURI,
				Scopes:         validScopes,
				PKCEChallenge:  codeChallenge,
				PKCEMethod:     codeChallengeMethod,
				ExpiresAt:      time.Now().Add(10 * time.Minute), // 10-minute expiration
				CreatedAt:      time.Now(),
			}
			err = store.SaveAuthCode(authCode)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "server_error",
					"error_description": "Failed to save authorization code",
				})
			}

			// Build the redirect URL with the code and state
			params := map[string]string{
				"code": code,
			}
			if state != "" {
				params["state"] = state
			}
			redirectURL, err := utils.BuildRedirectURI(redirectURI, params)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "server_error",
					"error_description": "Failed to build redirect URI",
				})
			}

			// Redirect the user to the client with the authorization code
			return c.Redirect(redirectURL)
		}

		// Render the login form
		return c.Render("login", fiber.Map{
			"csrf_token": c.Locals("csrf_token"),
			"client_name": client.Name,
			"scopes": validScopes,
		})
	}
}

// Token handles the OAuth 2.0 token endpoint
func Token(store models.Store, jwtService *models.JWTService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the grant type
		grantType := c.FormValue("grant_type")

		// Validate grant type (only 'authorization_code' and 'refresh_token' supported for now)
		if grantType != "authorization_code" && grantType != "refresh_token" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "unsupported_grant_type",
				"error_description": "Only 'authorization_code' and 'refresh_token' grant types are supported",
			})
		}

		// Get client credentials from Basic Auth or form params
		auth := c.Get("Authorization")
		clientID, clientSecret, ok := utils.ParseBasicAuth(auth)
		if !ok {
			// If not in basic auth, try form params (for public clients)
			clientID = c.FormValue("client_id")
			clientSecret = c.FormValue("client_secret")
			
			if clientID == "" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid_client",
					"error_description": "Client authentication required",
				})
			}
		}

		// Verify client
		client, err := store.GetClientByID(clientID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_client",
				"error_description": "Client ID is invalid",
			})
		}

		// For confidential clients, verify the secret
		if client.Secret != "" && !utils.CheckPasswordHash(clientSecret, client.Secret) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_client",
				"error_description": "Client credentials are invalid",
			})
		}

		// Handle grant types
		switch grantType {
		case "authorization_code":
			return handleAuthorizationCodeGrant(c, store, jwtService, client)
		case "refresh_token":
			return handleRefreshTokenGrant(c, store, jwtService, client)
		default:
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "unsupported_grant_type",
				"error_description": "Grant type not supported",
			})
		}
	}
}

// handleAuthorizationCodeGrant processes the authorization code grant type
func handleAuthorizationCodeGrant(c *fiber.Ctx, store models.Store, jwtService *models.JWTService, client *models.Client) error {
	// Get required parameters
	code := c.FormValue("code")
	redirectURI := c.FormValue("redirect_uri")
	codeVerifier := c.FormValue("code_verifier")

	// Validate the code
	authCode, err := store.GetAuthCode(code)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid_grant",
			"error_description": "Authorization code is invalid or expired",
		})
	}

	// Verify the client ID
	if authCode.ClientID != client.ID {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid_grant",
			"error_description": "Authorization code was not issued to this client",
		})
	}

	// Verify the redirect URI
	if authCode.RedirectURI != redirectURI {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid_grant",
			"error_description": "Redirect URI doesn't match the one used during authorization",
		})
	}

	// Verify PKCE if required
	if authCode.PKCEChallenge != "" {
		if codeVerifier == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_request",
				"error_description": "Code verifier is required",
			})
		}

		if !utils.VerifyPKCEChallenge(codeVerifier, authCode.PKCEChallenge, authCode.PKCEMethod) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_grant",
				"error_description": "Code verifier doesn't match code challenge",
			})
		}
	}

	// Get the user
	user, err := store.GetUserByID(authCode.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "server_error",
			"error_description": "Failed to get user information",
		})
	}

	// Delete the used authorization code
	err = store.DeleteAuthCode(code)
	if err != nil {
		// Just log this error, don't fail the request
		// In a real app, you'd want to log this somewhere
	}

	// Generate access token
	accessToken, accessJti, err := jwtService.GenerateAccessToken(
		user.ID, 
		client.ID, 
		user.Email, 
		authCode.Scopes,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "server_error",
			"error_description": "Failed to generate access token",
		})
	}

	// Generate refresh token
	refreshToken, refreshJti, err := jwtService.GenerateRefreshToken(user.ID, client.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "server_error",
			"error_description": "Failed to generate refresh token",
		})
	}

	// Store the tokens
	token := &models.Token{
		AccessJTI:  accessJti,
		RefreshJTI: refreshJti,
		UserID:     user.ID,
		ClientID:   client.ID,
		Scopes:     authCode.Scopes,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour), // 24-hour expiration for refresh token
	}
	err = store.SaveToken(token)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "server_error",
			"error_description": "Failed to save token",
		})
	}

	// Return the tokens
	return c.JSON(models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour (in seconds)
		RefreshToken: refreshToken,
		Scope:        utils.JoinScopes(authCode.Scopes),
	})
}

// handleRefreshTokenGrant processes the refresh token grant type
func handleRefreshTokenGrant(c *fiber.Ctx, store models.Store, jwtService *models.JWTService, client *models.Client) error {
	// Get the refresh token
	refreshToken := c.FormValue("refresh_token")
	if refreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid_request",
			"error_description": "Refresh token is required",
		})
	}

	// Validate the refresh token
	claims, err := jwtService.ValidateToken(refreshToken)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid_grant",
			"error_description": "Refresh token is invalid or expired",
		})
	}

	// Get the JTI from the claims
	jti, ok := claims["jti"].(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid_grant",
			"error_description": "Invalid refresh token format",
		})
	}

	// Find the token in the store
	oldToken, err := store.GetTokenByRefreshJTI(jti)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid_grant",
			"error_description": "Refresh token not found or revoked",
		})
	}

	// Verify the client ID
	if oldToken.ClientID != client.ID {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid_grant",
			"error_description": "Refresh token was not issued to this client",
		})
	}

	// Get the user
	user, err := store.GetUserByID(oldToken.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "server_error",
			"error_description": "Failed to get user information",
		})
	}

	// Revoke the old token
	err = store.DeleteToken(oldToken.AccessJTI)
	if err != nil {
		// Just log this error, don't fail the request
		// In a real app, you'd want to log this somewhere
	}

	// Generate new access token
	accessToken, accessJti, err := jwtService.GenerateAccessToken(
		user.ID, 
		client.ID, 
		user.Email, 
		oldToken.Scopes,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "server_error",
			"error_description": "Failed to generate access token",
		})
	}

	// Generate new refresh token
	newRefreshToken, refreshJti, err := jwtService.GenerateRefreshToken(user.ID, client.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "server_error",
			"error_description": "Failed to generate refresh token",
		})
	}

	// Store the new tokens
	newToken := &models.Token{
		AccessJTI:  accessJti,
		RefreshJTI: refreshJti,
		UserID:     user.ID,
		ClientID:   client.ID,
		Scopes:     oldToken.Scopes,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour), // 24-hour expiration for refresh token
	}
	err = store.SaveToken(newToken)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "server_error",
			"error_description": "Failed to save token",
		})
	}

	// Return the new tokens
	return c.JSON(models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour (in seconds)
		RefreshToken: newRefreshToken,
		Scope:        utils.JoinScopes(oldToken.Scopes),
	})
}

// RevokeToken handles the OAuth 2.0 token revocation endpoint
func RevokeToken(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the token to revoke
		token := c.FormValue("token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_request",
				"error_description": "Token is required",
			})
		}

		// Get token type hint
		tokenTypeHint := c.FormValue("token_type_hint") // "access_token" or "refresh_token"

		// Get client credentials from Basic Auth or form params
		auth := c.Get("Authorization")
		clientID, clientSecret, ok := utils.ParseBasicAuth(auth)
		if !ok {
			// If not in basic auth, try form params (for public clients)
			clientID = c.FormValue("client_id")
			clientSecret = c.FormValue("client_secret")
			
			if clientID == "" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid_client",
					"error_description": "Client authentication required",
				})
			}
		}

		// Verify client
		client, err := store.GetClientByID(clientID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_client",
				"error_description": "Client ID is invalid",
			})
		}

		// For confidential clients, verify the secret
		if client.Secret != "" && !utils.CheckPasswordHash(clientSecret, client.Secret) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_client",
				"error_description": "Client credentials are invalid",
			})
		}

		// Try to parse the token to get the JTI
		var tokenObj *jwt.Token
		tokenObj, _ = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return nil, nil // We don't actually validate here, just parse
		})

		// If we got claims, try to find and revoke the token
		if tokenObj != nil {
			if claims, ok := tokenObj.Claims.(jwt.MapClaims); ok {
				if jti, ok := claims["jti"].(string); ok {
					// Try to find the token by JTI
					if tokenTypeHint == "refresh_token" {
						if storedToken, err := store.GetTokenByRefreshJTI(jti); err == nil {
							store.DeleteToken(storedToken.AccessJTI)
						}
					} else {
						// Default to access token
						store.DeleteToken(jti)
					}
				}
			}
		}

		// Per OAuth 2.0 spec, always return success even if token wasn't found
		return c.Status(200).Send(nil)
	}
}

// IntrospectToken handles the OAuth 2.0 token introspection endpoint
func IntrospectToken(store models.Store, jwtService *models.JWTService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the token to introspect
		token := c.FormValue("token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_request",
				"error_description": "Token is required",
			})
		}

		// Get token type hint
		tokenTypeHint := c.FormValue("token_type_hint") // "access_token" or "refresh_token"

		// Get client credentials from Basic Auth or form params
		auth := c.Get("Authorization")
		clientID, clientSecret, ok := utils.ParseBasicAuth(auth)
		if !ok {
			// If not in basic auth, try form params (for public clients)
			clientID = c.FormValue("client_id")
			clientSecret = c.FormValue("client_secret")
			
			if clientID == "" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid_client",
					"error_description": "Client authentication required",
				})
			}
		}

		// Verify client
		client, err := store.GetClientByID(clientID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_client",
				"error_description": "Client ID is invalid",
			})
		}

		// For confidential clients, verify the secret
		if client.Secret != "" && !utils.CheckPasswordHash(clientSecret, client.Secret) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_client",
				"error_description": "Client credentials are invalid",
			})
		}

		// Validate the token
		claims, err := jwtService.ValidateToken(token)
		if err != nil {
			// If token is invalid, return inactive
			return c.JSON(models.IntrospectResponse{
				Active: false,
			})
		}

		// Extract token information
		jti, _ := claims["jti"].(string)
		sub, _ := claims["sub"].(string)
		clientID, _ = claims["client_id"].(string)
		exp, _ := claims["exp"].(float64)
		iat, _ := claims["iat"].(float64)
		scope, _ := claims["scope"].([]interface{})

		// Convert scope to string slice
		scopes := make([]string, 0)
		for _, s := range scope {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}

		// Check if the token exists in the store
		var storedToken *models.Token
		var tokenType string
		
		if tokenTypeHint == "refresh_token" {
			storedToken, err = store.GetTokenByRefreshJTI(jti)
			tokenType = "refresh_token"
		} else {
			// Default to access token
			storedToken, err = store.GetTokenByAccessJTI(jti)
			tokenType = "access_token"
		}

		if err != nil {
			// If token not found, return inactive
			return c.JSON(models.IntrospectResponse{
				Active: false,
			})
		}

		// Get user info
		user, err := store.GetUserByID(sub)
		if err != nil {
			// If user not found, return inactive
			return c.JSON(models.IntrospectResponse{
				Active: false,
			})
		}

		// Return active token information
		return c.JSON(models.IntrospectResponse{
			Active:    true,
			Scope:     utils.JoinScopes(storedToken.Scopes),
			ClientID:  clientID,
			Username:  user.Email,
			TokenType: tokenType,
			Exp:       int64(exp),
			Iat:       int64(iat),
			Jti:       jti,
		})
	}
}

// UserInfo handles the OpenID Connect UserInfo endpoint
func UserInfo(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the claims from the context
		claims, ok := c.Locals("claims").(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_token",
			})
		}

		// Get user ID from claims
		sub, ok := claims["sub"].(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_token",
			})
		}

		// Get scopes from claims
		scopeIntf, ok := claims["scope"].([]interface{})
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_token",
			})
		}

		// Convert scopes to string slice
		scopes := make([]string, 0)
		for _, s := range scopeIntf {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}

		// Get user from store
		user, err := store.GetUserByID(sub)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_token",
			})
		}

		// Build response based on scopes
		response := fiber.Map{
			"sub": user.ID,
		}

		// Include email if scope includes email
		if utils.Contains(scopes, "email") {
			response["email"] = user.Email
		}

		// Include profile info if scope includes profile
		if utils.Contains(scopes, "profile") {
			response["status"] = user.Status
			response["created_at"] = user.CreatedAt
		}

		return c.JSON(response)
	}
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