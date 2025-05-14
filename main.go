package main

import (
	"log"

	"github.com/dedisuhaimi/oauthsso/app/config"
	"github.com/dedisuhaimi/oauthsso/app/handlers"
	"github.com/dedisuhaimi/oauthsso/app/middleware"
	"github.com/dedisuhaimi/oauthsso/app/models"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
)

func main() {
	// Initialize in-memory data store
	store := models.NewInMemoryStore()

	// Setup configuration
	cfg := config.NewConfig()
	
	// Initialize JWT service
	jwtService := models.NewJWTService(cfg)

	// Setup template engine
	engine := html.New("./app/views", ".html")

	// Create Fiber app with template engine
	app := fiber.New(fiber.Config{
		ErrorHandler: handlers.ErrorHandler,
		Views:        engine,
		ReadBufferSize: 1024 * 1024, // 1MB
		BodyLimit:     1024 * 1024,  // 1MB
	})

	// Add configuration to locals
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("config", cfg)
		return c.Next()
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE",
	}))

	// Rate limiting middleware for auth endpoints
	authLimiter := middleware.RateLimiter(100, 60) // 100 requests per minute

	// OAuth Endpoints
	api := app.Group("/")
	
	// Client management
	api.Post("/clients", middleware.AdminAuth(), handlers.RegisterClient(store))
	
	// OAuth endpoints
	api.Get("/authorize", authLimiter, middleware.CSRFProtection(), handlers.Authorize(store))
	api.Post("/authorize", authLimiter, middleware.CSRFProtection(), handlers.Authorize(store))
	api.Post("/token", authLimiter, handlers.Token(store, jwtService))
	api.Post("/revoke", handlers.RevokeToken(store))
	api.Post("/introspect", handlers.IntrospectToken(store, jwtService))
	api.Get("/userinfo", middleware.ValidateToken(jwtService), handlers.UserInfo(store))
	
	// User management
	api.Post("/register", handlers.RegisterUser(store))
	api.Post("/confirm-email", handlers.ConfirmEmail(store))
	api.Post("/reset-password", handlers.ResetPassword(store))
	api.Put("/reset-password", handlers.ResetPassword(store))
	
	// Admin UI routes
	admin := app.Group("/admin", middleware.AdminAuth())
	admin.Get("/users", handlers.ListUsers(store))
	admin.Get("/clients", handlers.ListClients(store))

	// Start server
	log.Printf("Starting server on port %s", cfg.Port)
	log.Fatal(app.Listen(":" + cfg.Port))
} 