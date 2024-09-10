package handler

import (
	"auth/common"
	"auth/database"
	"auth/model"
	"auth/redis"
	"auth/util"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// CreateGrantType creates a new grant type record
func CreateGrantType(c *fiber.Ctx) error {

	// from middleware, if grant type is validated, grant type data will be in the Fiber context under the key "grantTypeRequest".
	data, ok := c.Locals("grantTypeRequest").(common.GrantTypeRequest)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", errors.New("cannot parse claim")))
	}

	grantType := model.GrantType{
		Name:        data.Name,
		Description: data.Description,
	}
	db := database.DB.Db

	result := db.Create(&grantType)
	if result.Error != nil {
		return c.Status(http.StatusBadRequest).
			JSON(util.ErrorResponse("Could not create grant type policy", result.Error))
	}

	key := common.GrantTypeRedisKey
	// from middleware, if grant type is validated, grant type data will be in the Fiber context under the key "grantTypeRequest".
	redisErr := util.RemoveKeyFromRedis(&key, 1)
	if redisErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", redisErr))
	}

	grantTypeArrayOfStringKey := common.GrantTypeNamesRedisKey

	redisErr = util.RemoveKeyFromRedis(&grantTypeArrayOfStringKey, 1)
	if redisErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", redisErr))
	}

	response := common.GrantTypePostReturnData{
		Name:        grantType.Name,
		Description: grantType.Description,
		CreatedAt:   grantType.CreatedAt,
		UpdatedAt:   grantType.UpdatedAt,
	}

	return c.Status(fiber.StatusCreated).JSON(util.SuccessResponse(response, "New grant type created"))

}

// UpdateGrantType updates a grant type by ID
func UpdateGrantType(c *fiber.Ctx) error {

	id := c.Params("id")

	data, ok := c.Locals("grantTypeRequest").(common.GrantTypeRequest)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", errors.New("cannot parse claim")))
	}

	var grantType model.GrantType

	// Update the grant type by ID
	db := database.DB.Db
	result := db.Model(&grantType).
		Where("id = ?", id).
		Updates(model.GrantType{
			Name:        data.Name,
			Description: data.Description,
		})

	if result.Error != nil {
		return c.Status(http.StatusInternalServerError).
			JSON(util.ErrorResponse("Internal Server Error", result.Error))
	}

	if result.RowsAffected == 0 {
		return c.Status(http.StatusNotFound).
			JSON(util.ErrorResponse("Grant Type not found", errors.New("no grant type found")))
	}

	key := common.GrantTypeRedisKey

	redisErr := util.RemoveKeyFromRedis(&key, 1)
	if redisErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", redisErr))
	}

	grantTypeArrayOfStringKey := common.GrantTypeNamesRedisKey

	redisErr = util.RemoveKeyFromRedis(&grantTypeArrayOfStringKey, 1)
	if redisErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", redisErr))
	}

	u, _ := uuid.Parse(id)
	response := common.GrantTypeResponse{
		ID:          u,
		Name:        grantType.Name,
		Description: grantType.Description,
		UpdatedAt:   grantType.UpdatedAt,
	}

	return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(response, "grant type updated"))

}

// DeleteGrantType Delete grant type deletes a Grant Type by ID
func DeleteGrantType(c *fiber.Ctx) error {
	db := database.DB.Db

	id := c.Params("id")

	if !util.ValidateUUIDv4(id) {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid request",
				errors.New("invalid id provided")))
	}

	if err := db.Where("id = ?", id).Delete(&model.GrantType{}).Error; err != nil {
		return c.Status(http.StatusBadRequest).
			JSON(util.ErrorResponse("Could not delete", err))
	}

	key := common.GrantTypeRedisKey

	redisErr := util.RemoveKeyFromRedis(&key, 1)
	if redisErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", redisErr))
	}

	grantTypeArrayOfStringKey := common.GrantTypeNamesRedisKey

	redisErr = util.RemoveKeyFromRedis(&grantTypeArrayOfStringKey, 1)
	if redisErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", redisErr))
	}

	emptyData := make(map[string]interface{})
	return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(emptyData, "grant type deleted"))
}

// GetAllGrantType GetGrantType retrieves a Grant type by ID
func GetAllGrantType(c *fiber.Ctx) error {

	// Key doesn't exist in Redis or redis returned error, fetch data from the database
	db := database.DB.Db
	var grantType []model.GrantType
	result := db.Find(&grantType)

	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Something went wrong", result.Error))
	} else if result.RowsAffected == 0 {
		return c.JSON(util.SuccessResponse([]model.GrantType{}, "No data found"))
	}

	//Convert model.GrantType objects to GrantTypeResponse
	var grantTypeData []common.GrantTypeResponse
	for _, p := range grantType {
		prd := common.GrantTypeResponse{
			ID:          p.ID,
			Name:        p.Name,
			Description: p.Description,
			CreatedAt:   p.CreatedAt,
			UpdatedAt:   p.UpdatedAt,
		}
		grantTypeData = append(grantTypeData, prd)
	}

	// Set the fetched data in Redis with an expiry of 24 hours
	key := common.GrantTypeRedisKey
	redisData, err := json.Marshal(grantTypeData)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Error encoding data for Redis", err))
	}

	err = redis.Client1.Set(database.Ctx, key, redisData, 24*time.Hour).Err()
	if err != nil {
		fmt.Println("Error setting value in Redis:", err)
		return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(grantTypeData, "grant type fetched from DB, but could not set in Redis"))
	}

	return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(grantTypeData, "grant type fetched from DB and set in Redis"))
}

// GetGrantType retrieves a grant type by ID
func GetGrantType(c *fiber.Ctx) error {

	db := database.DB.Db

	id := c.Params("id")

	if !util.ValidateUUIDv4(id) {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid request",
				errors.New("invalid id provided")))
	}

	var grantType model.GrantType
	if err := db.First(&grantType, "id = ?", id).Error; err != nil {
		return c.Status(fiber.StatusNotFound).
			JSON(util.ErrorResponse("No grant type found",
				errors.New("id not found")))
	}

	response := common.GrantTypeResponse{
		ID:          grantType.ID,
		Name:        grantType.Name,
		Description: grantType.Description,
		CreatedAt:   grantType.CreatedAt,
		UpdatedAt:   grantType.UpdatedAt,
	}

	return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(response, "grant type data"))

}
