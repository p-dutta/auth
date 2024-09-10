package handler

import (
	"auth/common"
	"auth/util"
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func GetToken(c *fiber.Ctx) error {

	/*logToFile := logger.GetForFile("get-token")
	logToFile.Info("from get token")*/

	/*fmt.Printf("Request URL: %s\n", c.OriginalURL())
	fmt.Printf("Request Method: %s\n", c.Method())
	fmt.Printf("Request IP: %s\n", c.IP())
	fmt.Printf("Request Host: %s\n", c.Host())
	fmt.Printf("Request Query String: %s\n", c.OriginalURL())
	fmt.Printf("Request Headers: %+v\n", c.Request().Header)
	fmt.Printf("Request Cookies: %+v\n", c.Cookies())
	fmt.Printf("Request Body: %s\n", c.Body())
	fmt.Printf("Request Query Params: %+v\n", c.Request().URI().QueryArgs())*/

	//var tokenInput common.TokenRequest
	tokenInput := *new(common.TokenRequest)

	if err := c.BodyParser(&tokenInput); err != nil {
		return c.Status(http.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid request body", err))
	}

	//fmt.Printf("TokenRequest: %+v\n", *tokenInput)
	//fmt.Printf("TokenInput: %+v\n", tokenInput)
	//fmt.Println(tokenInput.Type)

	// Commented out after the integration of dynamic grant/policy validator

	/*validate := custom_validator.CustomValidator

	if err := validate.Struct(&tokenInput); err != nil {

		//for _, e := range err.(custom_validator.ValidationErrors) {
		//	fmt.Printf("Field: %s, Error: %s\n", e.Field(), e.Tag())
		//	fmt.Println(e.Namespace())
		//	fmt.Println(e.Field())
		//	fmt.Println(e.StructNamespace())
		//	fmt.Println(e.StructField())
		//	fmt.Println(e.Tag())
		//	fmt.Println(e.ActualTag())
		//	fmt.Println(e.Kind())
		//	fmt.Println(e.Type())
		//	fmt.Println(e.Value())
		//	fmt.Println(e.Param())
		//	fmt.Println()
		//}
		//fmt.Printf("Error: %+v\n", err)

		var errs []*common.IError
		for _, err := range err.(validator.ValidationErrors) {
			var el common.IError
			el.Field = err.Field()
			el.Tag = err.Tag()
			el.Value = err.Value()
			errs = append(errs, &el)
			fmt.Println(el)
			fmt.Printf("Validation Error: Field %s failed validation for tag %s.", el.Field, el.Tag)
		}

		return c.Status(http.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid request body", err))

	}*/

	returnData, err := util.GenerateTokens(&tokenInput)

	if err != nil {
		return c.Status(http.StatusInternalServerError).
			JSON(util.ErrorResponse("Something went wrong", err))
	}

	return c.JSON(util.SuccessResponse(*returnData, "Tokens granted"))
}

func Refresh(c *fiber.Ctx) error {

	//refreshTokenDataPtr := c.Locals("refreshTokenDataPtr")
	/*
		refreshTokenDataPtr, ok := c.Locals("refreshTokenDataPtr").(*model.RefreshToken)
		if !ok {
			// Handle the case where the assertion fails
			// This could occur if the retrieved value isn't of type *model.RefreshToken
			return c.Status(fiber.StatusInternalServerError).JSON(
				util.ErrorResponse("Invalid token", errors.New("cannot parse claim")))
		}

		// At this point, refreshTokenDataPtr contains a pointer to type model.RefreshToken
		// can now use refreshTokenDataPtr directly as a pointer to refreshTokenData instance
	*/

	tokenClaimsPtr, ok := c.Locals("tokenClaimsPtr").(*common.TokenClaims)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(
			util.ErrorResponse("Something went wrong", errors.New("cannot parse claim")))
	}

	if tokenClaimsPtr != nil {

		tokenClaimsData := *tokenClaimsPtr

		if tokenClaimsData.Token != "refresh" {
			return c.Status(fiber.StatusBadRequest).JSON(
				util.ErrorResponse("Invalid token",
					errors.New("requesting with a non-refresh token")))
		}

		//tokenClaimsData.Token=access/refresh
		//tokenClaimsData.Type=device/subscriber/partner/admin/service

		refreshTokenDataPtr, err := util.GetRefreshTokenAgainstJti(&tokenClaimsData.Jti, &tokenClaimsData.Type)

		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(
				util.ErrorResponse("Unauthorized", err))
		}

		if refreshTokenDataPtr != nil {

			refreshTokenData := *refreshTokenDataPtr

			tokenReq := common.TokenRequest{
				Type:        refreshTokenData.Type,
				RequesterID: refreshTokenData.RequesterID, // Sample UUID
				DeviceID:    refreshTokenData.DeviceID,
				Provider:    refreshTokenData.Provider,
				Country:     refreshTokenData.Country,
			}

			redisErr := util.RemoveKeyFromRedis(&refreshTokenData.JTI, 0)
			if redisErr != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(
					util.ErrorResponse("Something went wrong", redisErr))
			}

			returnData, tokenGenErr := util.GenerateTokens(&tokenReq)

			if tokenGenErr != nil {
				return c.Status(http.StatusInternalServerError).
					JSON(util.ErrorResponse("Something went wrong", tokenGenErr))
			}

			return c.JSON(util.SuccessResponse(*returnData, "Tokens refreshed"))

		} else {
			return c.Status(fiber.StatusUnauthorized).JSON(
				util.ErrorResponse("Unauthorized", errors.New("invalid token")))

		}
	}

	return c.Status(fiber.StatusInternalServerError).JSON(
		util.ErrorResponse("Unauthorized", errors.New("no token-claims found")))

}

func Revoke(c *fiber.Ctx) error {
	// from middleware, if token is validated, claims data will be in the Fiber context under the key "tokenClaims".
	claims := c.Locals("tokenClaims")

	// Check if the "user" data exists
	if claims != nil {
		// Use the user data
		// For example, assuming userData is of type jwt.MapClaims:
		tokenClaims, ok := claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(
				util.ErrorResponse("Invalid token", errors.New("cannot parse claim")))
		}

		jti := tokenClaims["jti"].(string)

		if err := util.DeleteIfExistsInRedis(&jti); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(
				util.ErrorResponse(err.Error(), err))
		}

		if err := util.DeleteIfExistsInDB(&tokenClaims); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(
				util.ErrorResponse("Something went wrong", err))
		}

		emptyData := make(map[string]interface{})
		return c.JSON(util.SuccessResponse(emptyData, "Tokens revoked"))

	} else {
		return c.Status(fiber.StatusBadRequest).JSON(
			util.ErrorResponse(
				"Unauthorized", errors.New("invalid token")))

	}
}

func ValidateAccessToken(c *fiber.Ctx) error {
	// from middleware, if token is validated, claims data will be in the Fiber context under the key "tokenClaims".
	claims := c.Locals("tokenClaims")

	// Check if the "user" data exists
	if claims != nil {
		// Use the user data
		// For example, assuming userData is of type jwt.MapClaims:
		tokenClaims, ok := claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(
				util.ErrorResponse("Invalid token", errors.New("cannot parse claim")))
		}

		jti := tokenClaims["jti"].(string)

		redisDataPtr, err := util.CheckIfExistsInRedis(&jti)

		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(
				util.ErrorResponse("Not a whitelisted token", err))
		}

		redisData := *redisDataPtr

		returnData := common.ValidateTokenReturnData{
			Type:        tokenClaims["type"].(string),
			Token:       tokenClaims["token"].(string),
			Jti:         jti,
			Iat:         tokenClaims["iat"].(float64),
			Exp:         tokenClaims["exp"].(float64),
			Iss:         tokenClaims["iss"].(string),
			RequesterID: redisData.RequesterID,
			DeviceID:    redisData.DeviceID,
			Provider:    redisData.Provider,
			Country:     redisData.Country,
		}

		//emptyData := make(map[string]interface{})
		return c.JSON(util.SuccessResponse(returnData, "Valid token"))

	} else {
		return c.Status(fiber.StatusBadRequest).JSON(
			util.ErrorResponse(
				"Unauthorized", errors.New("invalid token")))
	}
}
