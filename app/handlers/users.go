package handlers

import (
	"time"

	"github.com/dedisuhaimi/oauthsso/app/models"
	"github.com/dedisuhaimi/oauthsso/app/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// RegisterUser handles user registration
func RegisterUser(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user data from request
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&input); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid input",
			})
		}

		// Validate email and password
		if input.Email == "" || input.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Email and password are required",
			})
		}

		// Check if user already exists
		_, err := store.GetUserByEmail(input.Email)
		if err == nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Email already registered",
			})
		}

		// Hash the password
		hashedPassword, err := utils.HashPassword(input.Password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to process registration",
			})
		}

		// Create the user
		user := &models.User{
			ID:             uuid.New().String(),
			Email:          input.Email,
			HashedPassword: hashedPassword,
			Status:         "pending", // Users start as pending until email is confirmed
			CreatedAt:      time.Now(),
		}

		err = store.CreateUser(user)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create user",
			})
		}

		// In a real app, would send confirmation email here

		// Return success (without exposing the full user object)
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"id":     user.ID,
			"email":  user.Email,
			"status": user.Status,
		})
	}
}

// ConfirmEmail handles email confirmation
func ConfirmEmail(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get token from request
		token := c.Query("token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Confirmation token is required",
			})
		}

		// In a real app, would validate the token against a stored value
		// For this demo, we'll fake it and just activate a user by email

		email := c.Query("email")
		if email == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Email is required",
			})
		}

		// Find the user
		user, err := store.GetUserByEmail(email)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}

		// Update the user status
		user.Status = "active"
		err = store.UpdateUser(user)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to update user",
			})
		}

		return c.JSON(fiber.Map{
			"message": "Email confirmed successfully",
		})
	}
}

// ResetPassword handles password reset
func ResetPassword(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// For a password reset request (step 1)
		if c.Method() == "POST" {
			// Get email from request
			var input struct {
				Email string `json:"email"`
			}

			if err := c.BodyParser(&input); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Invalid input",
				})
			}

			// Check if user exists
			user, err := store.GetUserByEmail(input.Email)
			if err != nil {
				// Don't reveal if the email exists or not for security
				return c.JSON(fiber.Map{
					"message": "If your email is registered, you will receive a password reset link",
				})
			}

			// In a real app, would generate a token and send a reset email
			// For this demo, just return success

			return c.JSON(fiber.Map{
				"message": "If your email is registered, you will receive a password reset link",
				"debug_user_id": user.ID, // Only for demo purposes
			})
		}

		// For the actual password reset (step 2)
		if c.Method() == "PUT" {
			// Get token and new password from request
			var input struct {
				Token       string `json:"token"`
				NewPassword string `json:"new_password"`
			}

			if err := c.BodyParser(&input); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Invalid input",
				})
			}

			// In a real app, would validate the token against a stored value
			// For this demo, we'll fake it and just reset the password directly

			userID := c.Query("user_id") // This would normally be encoded in the token
			if userID == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Invalid reset token",
				})
			}

			// Find the user
			user, err := store.GetUserByID(userID)
			if err != nil {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "User not found",
				})
			}

			// Hash the new password
			hashedPassword, err := utils.HashPassword(input.NewPassword)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to process password reset",
				})
			}

			// Update the password
			user.HashedPassword = hashedPassword
			err = store.UpdateUser(user)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to update password",
				})
			}

			// In a real app, would revoke all existing tokens for this user
			store.RevokeAllUserTokens(user.ID)

			return c.JSON(fiber.Map{
				"message": "Password reset successfully",
			})
		}

		return c.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{
			"error": "Method not allowed",
		})
	}
}

// ListUsers lists all users (admin only)
func ListUsers(store models.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		users, err := store.ListUsers()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to list users",
			})
		}

		// Don't expose password hashes
		type UserResponse struct {
			ID        string    `json:"id"`
			Email     string    `json:"email"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_at"`
		}

		response := make([]UserResponse, len(users))
		for i, user := range users {
			response[i] = UserResponse{
				ID:        user.ID,
				Email:     user.Email,
				Status:    user.Status,
				CreatedAt: user.CreatedAt,
			}
		}

		return c.JSON(response)
	}
} 