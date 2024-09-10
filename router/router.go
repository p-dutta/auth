package router

import (
	"auth/handler"
	"auth/middleware"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2"
)

// SetupRoutes setup router api
func SetupRoutes(app *fiber.App) {

	//api := app.Group(os.Getenv("ROUTE_PREFIX")+"/"+os.Getenv("API_VERSION"), logger.New())
	api := app.Group("/" + os.Getenv("API_VERSION"))

	// Health

	api.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})

	// Auth
	auth := api.Group("/token")
	auth.Post("", middleware.VerifyGrantType, handler.GetToken)
	auth.Post("/refresh", middleware.GetTokenClaimsFromHeader, handler.Refresh)
	auth.Post("/revoke", middleware.VerifyAccessToken, handler.Revoke)
	auth.Post("/verify", middleware.VerifyAccessToken, handler.ValidateAccessToken)

	// Policy
	policy := api.Group("/policy", middleware.VerifyAccessToken, middleware.IsSuperAdmin)

	policy.Post("", handler.CreatePolicy)
	policy.Get("", handler.GetAllPolicies)
	policy.Get("/:id", handler.GetPolicy)
	policy.Put("/:id", handler.UpdatePolicy)
	policy.Delete("/:id", handler.DeletePolicy)

	// Grant Type
	grantType := api.Group("/grant", middleware.VerifyAccessToken, middleware.IsSuperAdmin)
	grantType.Post("", middleware.VerifyValidGrantType, handler.CreateGrantType)
	grantType.Delete("/:id", handler.DeleteGrantType)
	grantType.Put("/:id", middleware.VerifyValidGrantType, handler.UpdateGrantType)
	grantType.Get("/:id", handler.GetGrantType)
	grantType.Get("", handler.GetAllGrantType)

}
