package handlers

import (
	"github.com/gofiber/fiber/v2"
)

// ErrorHandler is the global error handler for the application
func ErrorHandler(c *fiber.Ctx, err error) error {
	// Default status code is 500
	code := fiber.StatusInternalServerError

	// Check if it's a Fiber error
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	// Send error response
	return c.Status(code).JSON(fiber.Map{
		"error": err.Error(),
	})
} 