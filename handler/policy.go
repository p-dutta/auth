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
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CreatePolicy creates a new Policy record

func CreatePolicy(c *fiber.Ctx) error {

	db := database.DB.Db

	policyInput := *new(common.PolicyRequest)

	if err := c.BodyParser(&policyInput); err != nil {
		return c.Status(http.StatusBadRequest).JSON(util.ErrorResponse("Invalid request body", err))
	}

	var policy model.Policy

	result := db.First(&policy, "Lower(type) = ?", strings.ToLower(policyInput.Type))

	var grantType model.GrantType
	grantTypeResult := db.First(&grantType, "Lower(name) = ?", strings.ToLower(policyInput.Type))
	if errors.Is(grantTypeResult.Error, gorm.ErrRecordNotFound) {
		return c.Status(http.StatusBadRequest).
			JSON(util.ErrorResponse("No grant type for this policy", errors.New("grant type does not exist")))

	}

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		policy := model.Policy{
			Type:     policyInput.Type,
			AtExpiry: policyInput.AtExpiry,
			RtExpiry: policyInput.RtExpiry,
			Iss:      policyInput.Iss,
		}

		result := db.Create(&policy)
		if result.Error != nil {
			return c.Status(http.StatusBadRequest).
				JSON(util.ErrorResponse("Could not create policy", result.Error))
		}

		key := common.PolicyRedisKey

		redisErr := util.RemoveKeyFromRedis(&key, 1)
		if redisErr != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(
				util.ErrorResponse("Something went wrong", redisErr))
		}

		returnData := common.PolicyReturnData{
			ID:        policy.ID,
			Type:      policy.Type,
			AtExpiry:  policy.AtExpiry,
			RtExpiry:  policy.RtExpiry,
			Iss:       policy.Iss,
			CreatedAt: policy.CreatedAt,
			UpdatedAt: policy.UpdatedAt,
		}

		return c.Status(fiber.StatusCreated).JSON(util.SuccessResponse(returnData, "New policy created"))
	} else {

		return c.Status(fiber.StatusConflict).JSON(
			util.ErrorResponse("Policy already exists against this type",
				errors.New("policy already exists against this type")))

	}

}

// GetPolicy retrieves a Policy by ID
func GetPolicy(c *fiber.Ctx) error {

	db := database.DB.Db

	id := c.Params("id")

	if !util.ValidateUUIDv4(id) {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid request",
				errors.New("invalid id provided")))
	}

	var policy model.Policy
	if err := db.First(&policy, "id = ?", id).Error; err != nil {
		return c.Status(fiber.StatusNotFound).
			JSON(util.ErrorResponse("No policy found",
				errors.New("id not found")))
	}

	returnData := common.PolicyReturnData{
		ID:        policy.ID,
		Type:      policy.Type,
		AtExpiry:  policy.AtExpiry,
		RtExpiry:  policy.RtExpiry,
		Iss:       policy.Iss,
		CreatedAt: policy.CreatedAt,
		UpdatedAt: policy.UpdatedAt,
	}

	//return c.JSON(policy)

	return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(returnData, "policy data"))

}

/*func GetAllPolicies(c *fiber.Ctx) error {
	redisClient := database.CreateRedisClient(1)
	key := "policies"
	var policyData []common.PolicyReturnData

	// Check if the key exists in Redis
	data, err := redisClient.Get(database.Ctx, key).Result()
	if err == nil {
		err = json.Unmarshal([]byte(data), &policyData)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).
				JSON(util.ErrorResponse("Error decoding Redis data", err))
		}
		return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(policyData, "Policies retrieved from Redis"))

	}

	// Key doesn't exist in Redis or redis returned error, fetch data from the database
	db := database.DB.Db
	var policies []model.Policy
	result := db.Find(&policies)

	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Something went wrong", result.Error))
	} else if result.RowsAffected == 0 {
		return c.JSON(util.SuccessResponse([]model.Policy{}, "No data found"))
	}

	// Convert model.Policy objects to PolicyReturnData
	for _, p := range policies {
		prd := common.PolicyReturnData{
			ID:        p.ID,
			Type:      p.Type,
			AtExpiry:  p.AtExpiry,
			RtExpiry:  p.RtExpiry,
			Iss:       p.Iss,
			CreatedAt: p.CreatedAt,
			UpdatedAt: p.UpdatedAt,
		}
		policyData = append(policyData, prd)
	}

	// Set the fetched data in Redis with an expiry of 60 minutes
	redisData, err := json.Marshal(policyData)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Error encoding data for Redis", err))
	}

	err = redisClient.Set(database.Ctx, key, redisData, 24*time.Hour).Err()
	if err != nil {
		fmt.Println("Error setting value in Redis:", err)
		return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(policyData, "Policies fetched from DB, but could not set in Redis"))
	}

	return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(policyData, "Policies fetched from DB and set in Redis"))
}*/

func GetAllPolicies(c *fiber.Ctx) error {
	//redisClient := database.CreateRedisClient(1)
	//defer database.CloseRedisClient(redisClient)
	key := common.PolicyRedisKey
	var policyData []common.PolicyReturnData

	// Pagination parameters
	page, err := strconv.Atoi(c.Query("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(c.Query("limit", "10")) // Default limit: 10 items per page
	if err != nil || limit < 1 {
		limit = 10
	}
	offset := (page - 1) * limit

	// Check if the key exists in Redis
	data, err := redis.Client1.Get(database.Ctx, key).Result()
	if err == nil {
		err = json.Unmarshal([]byte(data), &policyData)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).
				JSON(util.ErrorResponse("Error decoding Redis data", err))
		}
		// Paginate the fetched data
		paginatedData := paginate(policyData, offset, limit)
		return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(paginatedData, "Policies retrieved from Redis"))
	}

	// Key doesn't exist in Redis or redis returned error, fetch data from the database
	db := database.DB.Db
	var policies []model.Policy
	result := db.Limit(limit).Offset(offset).Find(&policies)

	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Something went wrong", result.Error))
	} else if result.RowsAffected == 0 {
		return c.JSON(util.SuccessResponse([]model.Policy{}, "No data found"))
	}

	// Convert model.Policy objects to PolicyReturnData
	for _, p := range policies {
		prd := common.PolicyReturnData{
			ID:        p.ID,
			Type:      p.Type,
			AtExpiry:  p.AtExpiry,
			RtExpiry:  p.RtExpiry,
			Iss:       p.Iss,
			CreatedAt: p.CreatedAt,
			UpdatedAt: p.UpdatedAt,
		}
		policyData = append(policyData, prd)
	}

	// Set the fetched data in Redis with an expiry of 60 minutes
	redisData, err := json.Marshal(policyData)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Error encoding data for Redis", err))
	}

	err = redis.Client1.Set(database.Ctx, key, redisData, 24*time.Hour).Err()
	if err != nil {
		fmt.Println("Error setting value in Redis:", err)
		return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(policyData, "Policies fetched from DB, but could not set in Redis"))
	}

	// Paginate the fetched data
	paginatedData := paginate(policyData, offset, limit)
	return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(paginatedData, "Policies fetched from DB and set in Redis"))
}

// Function to paginate data
func paginate(data []common.PolicyReturnData, offset, limit int) []common.PolicyReturnData {
	if offset >= len(data) {
		return []common.PolicyReturnData{}
	}
	end := offset + limit
	if end > len(data) {
		end = len(data)
	}
	return data[offset:end]
}

// UpdatePolicy updates a Policy by ID

func UpdatePolicy(c *fiber.Ctx) error {
	db := database.DB.Db
	//db.LogMode(true)
	id := c.Params("id")

	if !util.ValidateUUIDv4(id) {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid request",
				errors.New("invalid id provided")))
	}

	policyInput := *new(common.PolicyRequest)

	if err := c.BodyParser(&policyInput); err != nil {
		return c.Status(http.StatusBadRequest).JSON(util.ErrorResponse("Invalid request body", err))
	}

	// validate := custom_validator.PolicyValidator

	// if err := validate.Struct(&policyInput); err != nil {

	// 	var errs []*common.IError
	// 	for _, err := range err.(validator.ValidationErrors) {
	// 		var el common.IError
	// 		el.Field = err.Field()
	// 		el.Tag = err.Tag()
	// 		el.Value = err.Value()
	// 		errs = append(errs, &el)
	// 		fmt.Println(el)
	// 		fmt.Printf("Validation Error: Field %s failed validation for tag %s.", el.Field, el.Tag)
	// 	}

	// 	return c.Status(http.StatusBadRequest).
	// 		JSON(util.ErrorResponse("Invalid request body", err))

	// }

	var grantType model.GrantType
	grantTypeResult := db.First(&grantType, "Lower(name) = ?", strings.ToLower(policyInput.Type))
	if errors.Is(grantTypeResult.Error, gorm.ErrRecordNotFound) {
		return c.Status(http.StatusBadRequest).
			JSON(util.ErrorResponse("Could not create policy", errors.New("grant type not exists")))

	}

	// check if a policy already exists against this type in some other id
	existingData := db.Not("id = ?", id).First(&model.Policy{}, "type = ?", policyInput.Type)

	if errors.Is(existingData.Error, gorm.ErrRecordNotFound) {
		var policy model.Policy

		/*if err := db.Model(&model.Policy{}).Where("id = ?", id).Updates(&policyInput).Error; err != nil {
			// Handle error (record not found or any other error)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Policy not found"})
		}*/

		// Update the policy by ID
		result := db.Model(&policy).
			//Where("type = ?", policyInput.Type).
			Where("id = ?", id).
			//Where("id = ? AND type = ?", id, policyInput.Type).
			Updates(model.Policy{
				Type:     policyInput.Type,
				AtExpiry: policyInput.AtExpiry,
				RtExpiry: policyInput.RtExpiry,
				Iss:      policyInput.Iss,
			})

		if result.Error != nil {
			return c.Status(http.StatusInternalServerError).
				JSON(util.ErrorResponse("Internal Server Error", result.Error))
		}

		if result.RowsAffected == 0 {
			return c.Status(http.StatusNotFound).
				JSON(util.ErrorResponse("Policy not found", errors.New("no policy found")))
		}

		key := common.PolicyRedisKey

		redisErr := util.RemoveKeyFromRedis(&key, 1)
		if redisErr != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(
				util.ErrorResponse("Something went wrong", redisErr))
		}

		u, _ := uuid.Parse(id)
		returnData := common.PolicyReturnData{
			ID:        u,
			Type:      policyInput.Type,
			AtExpiry:  policyInput.AtExpiry,
			RtExpiry:  policyInput.RtExpiry,
			Iss:       policyInput.Iss,
			UpdatedAt: policy.UpdatedAt,
		}

		return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(returnData, "Policy updated"))

	} else {
		return c.Status(fiber.StatusConflict).JSON(
			util.ErrorResponse("Cannot update a policy to an existing type",
				errors.New("policy already exists against this type")))
	}
}

// DeletePolicy deletes a Policy by ID
func DeletePolicy(c *fiber.Ctx) error {
	db := database.DB.Db

	id := c.Params("id")

	if !util.ValidateUUIDv4(id) {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid request",
				errors.New("invalid id provided")))
	}

	if err := db.Where("id = ?", id).Delete(&model.Policy{}).Error; err != nil {
		return c.Status(http.StatusBadRequest).
			JSON(util.ErrorResponse("Could not delete", err))
	}

	key := common.PolicyRedisKey

	redisErr := util.RemoveKeyFromRedis(&key, 1)
	if redisErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", redisErr))
	}

	emptyData := make(map[string]interface{})
	return c.Status(fiber.StatusOK).JSON(util.SuccessResponse(emptyData, "Policy deleted"))
}
