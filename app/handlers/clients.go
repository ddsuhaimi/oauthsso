package handlers

import (
	"time"

	"github.com/dedisuhaimi/oauthsso/app/models"
	"github.com/dedisuhaimi/oauthsso/app/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// RegisterClient handles OAuth client registration
func RegisterClient(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get client data from request
		var input struct {
			Name         string   `json:"name"`
			RedirectURIs []string `json:"redirect_uris"`
			Scopes       []string `json:"scopes"`
		}

		if err := c.BodyParser(&input); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid input",
			})
		}

		// Validate required fields
		if input.Name == "" || len(input.RedirectURIs) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Name and at least one redirect URI are required",
			})
		}

		// Generate client ID and secret
		clientID := uuid.New().String()
		clientSecret, err := utils.GenerateRandomString(32)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to generate client credentials",
			})
		}

		// Hash the client secret for storage
		hashedSecret, err := utils.HashPassword(clientSecret)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to process client registration",
			})
		}

		// Use default scopes if none provided
		if len(input.Scopes) == 0 {
			input.Scopes = []string{"openid", "profile", "email"}
		}

		// Create the client
		client := &models.Client{
			ID:           clientID,
			Secret:       hashedSecret,
			Name:         input.Name,
			RedirectURIs: input.RedirectURIs,
			Scopes:       input.Scopes,
			CreatedAt:    time.Now(),
		}

		err = store.CreateClient(client)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to register client",
			})
		}

		// Return the client credentials
		// Note: This is the only time the client secret is returned in plaintext
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"client_id":     clientID,
			"client_secret": clientSecret, // Only returned once
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
			"scopes":        client.Scopes,
		})
	}
}

// ListClients lists all OAuth clients (admin only)
func ListClients(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		clients, err := store.ListClients()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to list clients",
			})
		}

		// Don't expose client secrets
		type ClientResponse struct {
			ID           string    `json:"id"`
			Name         string    `json:"name"`
			RedirectURIs []string  `json:"redirect_uris"`
			Scopes       []string  `json:"scopes"`
			CreatedAt    time.Time `json:"created_at"`
		}

		response := make([]ClientResponse, len(clients))
		for i, client := range clients {
			response[i] = ClientResponse{
				ID:           client.ID,
				Name:         client.Name,
				RedirectURIs: client.RedirectURIs,
				Scopes:       client.Scopes,
				CreatedAt:    client.CreatedAt,
			}
		}

		return c.JSON(response)
	}
}