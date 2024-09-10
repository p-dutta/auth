package middleware

import (
	"auth/logger"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"runtime/debug"
)

func RecoverFromPanic(c *fiber.Ctx) error {
	defer func() {
		if r := recover(); r != nil {
			//fmt.Println("Recovered from panic:", r)
			log := logger.GetForFile("panics")
			log.Error("Recovered from panic",
				zap.String("panic", fmt.Sprintf("%v", r)),
				zap.String("requestPath", c.Path()),
				zap.String("method", c.Method()),
			)
			debug.PrintStack()
			// Send an HTTP 500 response when a panic is recovered
			c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"data":    make(map[string]interface{}),
				"message": "Something went wrong",
				"error":   "Internal Server Error: " + fmt.Sprintf("%v", r),
			})
		}
	}()
	return c.Next()
}
