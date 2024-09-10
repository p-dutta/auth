package middleware

import (
	"auth/common"
	"auth/database"
	"auth/logger"
	"auth/model"
	"auth/redis"
	"auth/util"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

func VerifyAccessToken(c *fiber.Ctx) error {
	reqPath := c.Path()

	authorizationHeader := c.Get("Authorization")

	tokenString, err := util.GetTokenFromHeader(&authorizationHeader)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid token", err))
	}

	/*var tokenString string
	tokenString = *token*/

	//return c.Next()

	publicKeyBytes := *util.PublicKeyContent

	// Parse the public key and create a verification key function.
	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Error parsing public key",
				errors.New("error parsing public key")))
	}

	// Parse and verify the token.
	token, err := jwt.Parse(*tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		log := logger.GetForFile("access-token")
		log.Error("Error while verifying access token",
			zap.String("method", c.Method()),
			zap.String("api", c.Path()),
			zap.String("auth", c.Get("Authorization")),
			zap.String("userinfo", c.Get("X-Decoded-Payload")),
			//zap.Any("headers", c.GetReqHeaders()),
			zap.Error(err),
		)

		if errors.Is(err, jwt.ErrTokenMalformed) {
			return c.Status(fiber.StatusBadRequest).
				JSON(util.ErrorResponse("Malformed token", err))
		} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return c.Status(fiber.StatusUnauthorized).
				JSON(util.ErrorResponse("Token expired or not active yet", err))
		} else {
			return c.Status(fiber.StatusBadRequest).JSON(util.ErrorResponse("Invalid token", err))
		}
	}

	if !token.Valid {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid token", errors.New("token is not valid")))
	}

	// If verification succeeds, set the claims in the context and proceed
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid token claims", errors.New("invalid token claims")))
	}

	tokenType := claims["type"].(string)

	if strings.Contains(reqPath, "policy") {
		if strings.ToLower(tokenType) != common.SuperAdmin {
			return c.Status(fiber.StatusBadRequest).
				JSON(util.ErrorResponse("You are not authorized to make this request",
					errors.New("only an super admin can make this request")))
		}
	}

	if strings.Contains(reqPath, "grant") {
		if strings.ToLower(tokenType) != common.SuperAdmin {
			return c.Status(fiber.StatusBadRequest).
				JSON(util.ErrorResponse("You are not authorized to make this request",
					errors.New("only an super admin can make this request")))
		}
	}

	accessType := claims["token"].(string)

	if accessType == "refresh" {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid token",
				errors.New("requesting with a refresh token")))

	}

	c.Locals("tokenClaims", claims)
	return c.Next()
}

func VerifyRefreshToken(c *fiber.Ctx) error {

	authorizationHeader := c.Get("Authorization")

	tokenString, err := util.GetTokenFromHeader(&authorizationHeader)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid token", err))
	}

	//fmt.Println(tokenString)

	// Load your public key from a file or any other source.
	/*publicKeyPath := "./public_key.pem"
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Something went wrong",
				errors.New("error reading public key")))
	}*/

	publicKeyBytes := *util.PublicKeyContent

	// Parse the public key and create a verification key function.
	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			JSON(util.ErrorResponse("Error parsing public key",
				errors.New("error parsing public key")))
	}

	// Parse and verify the token.
	token, err := jwt.Parse(*tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {

		log := logger.GetForFile("refresh-token")

		//log.Error("Malformed token")

		//log.Error("Error occurred", zap.Error(err), zap.Duration("durationField", time.Second*3))
		log.Error("Error while refreshing token",
			zap.String("method", c.Method()),
			zap.String("api", c.Path()),
			zap.Error(err),
		)

		if errors.Is(err, jwt.ErrTokenMalformed) {
			return c.Status(fiber.StatusBadRequest).
				JSON(util.ErrorResponse("Malformed token", err))
		} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return c.Status(fiber.StatusUnauthorized).
				JSON(util.ErrorResponse("Token expired or not active yet", err))
		} else {
			return c.Status(fiber.StatusBadRequest).JSON(util.ErrorResponse("Invalid token", err))
		}

	}

	if !token.Valid {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid token", errors.New("token is not valid")))
	}

	// If verification succeeds, set the claims in the context and proceed
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid token claims", errors.New("invalid token claims")))
	}

	accessType := claims["token"].(string)

	if accessType == "access" {
		log := logger.GetForFile("refresh-token")
		log.Error("Error while refreshing token",
			zap.String("method", c.Method()),
			zap.String("api", c.Path()),
			zap.Error(errors.New("requesting with an access token")),
		)

		return c.Status(fiber.StatusBadRequest).
			JSON(util.ErrorResponse("Invalid token",
				errors.New("requesting with an access token")))

	}

	refreshTokenDataPtr, err := util.CheckIfJtiExistsInDB(&claims)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			util.ErrorResponse("Unauthorized", err))
	}

	c.Locals("refreshTokenDataPtr", refreshTokenDataPtr)
	return c.Next()
}

/*
GetTokenClaimsFromHeader gets the token claims from the header and sets it in the Fiber context
*/

func GetTokenClaimsFromHeader(c *fiber.Ctx) error {

	decodedPayload := c.Get("X-Decoded-Payload")
	var tokenClaims *common.TokenClaims

	if decodedPayload == "" {
		decodedPayload = c.Get("X-Apigateway-Api-Userinfo")

		if decodedPayload == "" {
			return c.Status(fiber.StatusBadRequest).JSON(
				util.ErrorResponse("Bad request", errors.New("no decoded claim")))
		}

		// have to add padding to the end of the string if it is not a multiple of 4
		if i := len(decodedPayload) % 4; i != 0 {
			decodedPayload += strings.Repeat("=", 4-i)
		}

		base64DecodedUserInfo, err := base64.StdEncoding.DecodeString(decodedPayload)
		if err != nil {
			log := logger.GetForFile("refresh-token")
			log.Error("Error while verifying token",
				zap.String("userinfo", c.Get("X-Apigateway-Api-Userinfo")),
				zap.Any("headers", c.GetReqHeaders()),
				zap.Error(err),
			)

			return c.Status(fiber.StatusBadRequest).JSON(
				util.ErrorResponse("Error decoding header payload", err))
		}

		if err = json.Unmarshal(base64DecodedUserInfo, &tokenClaims); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(
				util.ErrorResponse("Error parsing token claims", err))
		}

		c.Locals("tokenClaimsPtr", tokenClaims)
		return c.Next()
	}

	err := json.Unmarshal([]byte(decodedPayload), &tokenClaims)
	if err != nil {
		log := logger.GetForFile("refresh-token")
		log.Error("Error while verifying access token",
			zap.String("X-Decoded-Payload", c.Get("X-Decoded-Payload")),
			zap.Any("headers", c.GetReqHeaders()),
			zap.Error(err),
		)

		return c.Status(fiber.StatusBadRequest).JSON(
			util.ErrorResponse("Error decoding header payload2", err))
	}

	c.Locals("tokenClaimsPtr", tokenClaims)
	return c.Next()
}

func GetTokenClaimsFromHeaderApigee(c *fiber.Ctx) error {
	decodedPayload := c.Get("X-Decoded-Payload")
	var tokenClaims *common.TokenClaims
	err := json.Unmarshal([]byte(decodedPayload), &tokenClaims)
	if err != nil {
		log := logger.GetForFile("refresh-token")
		log.Error("Error while verifying access token",
			zap.String("X-Decoded-Payload", c.Get("X-Decoded-Payload")),
			zap.Any("headers", c.GetReqHeaders()),
			zap.Error(err),
		)

		return c.Status(fiber.StatusBadRequest).JSON(
			util.ErrorResponse("Error decoding header payload", err))
	}
	c.Locals("tokenClaimsPtr", tokenClaims)
	return c.Next()
}

func VerifyGrantType(c *fiber.Ctx) error {
	tokenInput := *new(common.TokenRequest)
	if err := c.BodyParser(&tokenInput); err != nil {
		return c.Status(http.StatusBadRequest).JSON(util.ErrorResponse("Invalid request body", err))
	}

	var cacheGrantTypes []string
	var found bool

	// Check if the key exists in Redis
	key := common.GrantTypeNamesRedisKey
	data, err := redis.Client1.Get(database.Ctx, key).Result()

	if err == nil {
		err = json.Unmarshal([]byte(data), &cacheGrantTypes)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).
				JSON(util.ErrorResponse("Error decoding Redis data", err))
		}

		for _, grantType := range cacheGrantTypes {
			if grantType == strings.ToLower(tokenInput.Type) {
				return c.Next()
			}
		}

		if found == false {
			return c.Status(http.StatusBadRequest).
				JSON(util.ErrorResponse("Grant type does not exist", errors.New("grant type does not exist")))
		}

	} else {
		// fetch all grant type data from the database
		db := database.DB.Db
		var grantType []model.GrantType
		result := db.Find(&grantType)

		if result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).
				JSON(util.ErrorResponse("Something went wrong", result.Error))
		} else if result.RowsAffected == 0 {
			return c.Status(http.StatusBadRequest).
				JSON(util.ErrorResponse("Grant type does not exist", errors.New("grant type does not exist")))
		}

		var grantTypes []string

		for i := 0; i < len(grantType); i++ {
			if strings.ToLower(grantType[i].Name) == strings.ToLower(tokenInput.Type) {
				found = true
			}
			grantTypes = append(grantTypes, strings.ToLower(grantType[i].Name))

		}

		if found == false {
			return c.Status(http.StatusBadRequest).
				JSON(util.ErrorResponse("Grant type does not exist", errors.New("grant type does not exist")))

		}
		// Set the fetched data in Redis with an expiry of 24 hours

		key := common.GrantTypeNamesRedisKey
		redisData, err := json.Marshal(grantTypes)
		if err != nil {
			log := logger.GetForFile("verify_grant_type")
			log.Error("could not unmarshal grant type from Redis",
				zap.Error(err))
			return c.Next()

		}

		err = redis.Client1.Set(database.Ctx, key, redisData, 24*time.Hour).Err()
		if err != nil {
			log := logger.GetForFile("verify_grant_type")
			log.Error("grant type fetched from DB, but could not set in Redis",
				zap.Error(err))
			return c.Next()

		}

		return c.Next()
	}
	return c.Status(http.StatusBadRequest).
		JSON(util.ErrorResponse("Grant type does not exist", errors.New("grant type does not exist")))

}

func VerifyValidGrantType(c *fiber.Ctx) error {
	data := *new(common.GrantTypeRequest)

	if err := c.BodyParser(&data); err != nil {
		return c.Status(http.StatusBadRequest).JSON(util.ErrorResponse("Invalid request body", err))
	}

	var grantType model.GrantType
	db := database.DB.Db
	result := db.First(&grantType, "Lower(name) = ?", strings.ToLower(data.Name))

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		c.Locals("grantTypeRequest", data)
		return c.Next()
	} else {
		return c.Status(fiber.StatusConflict).JSON(
			util.ErrorResponse("Grant type already exists against this type",
				errors.New("grant type already exists against this type")))

	}

}

func IsSuperAdmin(c *fiber.Ctx) error {
	decodedPayload := c.Get("X-Decoded-Payload")
	var tokenClaims *common.TokenClaims

	if decodedPayload == "" {
		decodedPayload = c.Get("X-Apigateway-Api-Userinfo")
		// have to add padding to the end of the string if it is not a multiple of 4
		if i := len(decodedPayload) % 4; i != 0 {
			decodedPayload += strings.Repeat("=", 4-i)
		}

		base64DecodedUserInfo, err := base64.StdEncoding.DecodeString(decodedPayload)
		if err != nil {

			return c.Status(fiber.StatusBadRequest).JSON(
				util.ErrorResponse("Error decoding header payload", err))
		}

		if err = json.Unmarshal(base64DecodedUserInfo, &tokenClaims); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(
				util.ErrorResponse("Error parsing token claims", err))
		}

	}

	if decodedPayload == "" {
		return c.Status(fiber.StatusBadRequest).JSON(
			util.ErrorResponse("Bad request", errors.New("no decoded claim")))
	}

	err := json.Unmarshal([]byte(decodedPayload), &tokenClaims)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			util.ErrorResponse("Error decoding header payload", err))
	}

	if tokenClaims.Type != common.SuperAdmin {
		return c.Status(fiber.StatusUnauthorized).
			JSON(util.ErrorResponse("You are not authorized to make this request", err))
	}

	return c.Next()

}
