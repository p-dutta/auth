package util

import (
	"github.com/gofiber/fiber/v2"
)

// ErrorResponse is the ErrorResponse that will be passed in the response by Handler
func ErrorResponse(msg string, err error) *fiber.Map {
	return &fiber.Map{
		"success": false,
		"data":    make(map[string]interface{}),
		"message": msg,
		"error":   err.Error(),
	}
}

func SuccessResponse(data interface{}, msg string) *fiber.Map {
	return &fiber.Map{
		"success": true,
		"data":    data,
		"message": msg,
	}
}
