package util

import (
	"auth/common"
	"auth/database"
	"auth/logger"
	"auth/model"
	"auth/redis"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	goRedis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func GenerateTokens(tokenRequest *common.TokenRequest) (*common.TokenReturnData, error) {

	var accessTokenExpiresIn int64
	var refreshTokenExpiresIn int64
	var issuer string

	if tokenRequest.AccessTokenExp != 0 && tokenRequest.RefreshTokenExp != 0 {
		accessTokenExpiresIn = tokenRequest.AccessTokenExp
		refreshTokenExpiresIn = tokenRequest.RefreshTokenExp
		issuer = "toffeelive.com"
	} else {
		var policyData []common.PolicyReturnData
		// get all policies
		policyDataPtr, err := GetPolicyData()

		if err != nil {
			return nil, err
		}

		policyData = *policyDataPtr

		policyExists := 0

		for _, policy := range policyData {
			if policy.Type == tokenRequest.Type {
				policyExists = 1
				accessTokenExpiresIn = policy.AtExpiry
				refreshTokenExpiresIn = policy.RtExpiry
				issuer = policy.Iss
				break
			}
		}

		if policyExists == 0 {
			return nil, errors.New("no policy found against this token type")
		}

	}

	// Get the current time.
	currentTime := time.Now()

	// Add one month (30 days) to the current time.
	//accessTokenExpiry := currentTime.AddDate(0, 0, 30).Unix()
	//accessTokenExpiry := currentTime.AddDate(0, 0, 30).Unix()
	//oneMonthLater := currentTime.Add(1 * time.Minute).Unix()
	//oneYearLater := currentTime.Add(2 * time.Minute).Unix()

	accessTokenExpiry := currentTime.Add(time.Duration(accessTokenExpiresIn) * time.Second).Unix()
	refreshTokenExpiry := currentTime.Add(time.Duration(refreshTokenExpiresIn) * time.Second).Unix()

	jti := GenerateUniqueJTI()

	accessTokenClaims := jwt.MapClaims{
		"type":     tokenRequest.Type,
		"token":    "access",
		"jti":      jti,
		"iat":      currentTime.Unix(),
		"exp":      accessTokenExpiry,
		"iss":      issuer,
		"country":  tokenRequest.Country,
		"provider": tokenRequest.Provider,
		"aud":      os.Getenv("TOKEN_ISSUER"),
	}

	refreshTokenClaims := jwt.MapClaims{
		"type":     tokenRequest.Type,
		"token":    "refresh",
		"jti":      jti,
		"iat":      currentTime.Unix(),
		"exp":      refreshTokenExpiry,
		"iss":      issuer,
		"country":  tokenRequest.Country,
		"provider": tokenRequest.Provider,
		"aud":      os.Getenv("TOKEN_ISSUER"),
	}

	generatedAccessToken, err := GenerateJWT(accessTokenClaims)
	generatedRefreshToken, err := GenerateJWT(refreshTokenClaims)

	if err != nil {
		return nil, err
	}
	//success := StoreAccessTokenToRedis(&tokenRequest.DeviceID, &jti)
	success := StoreAccessTokenToRedis(&jti, tokenRequest, accessTokenExpiresIn)

	if !success {
		return nil, err
	}

	db := database.DB.Db
	var refreshToken model.RefreshToken

	result := db.Where(&model.RefreshToken{
		RequesterID: tokenRequest.RequesterID,
		DeviceID:    tokenRequest.DeviceID,
		Type:        strings.ToLower(tokenRequest.Type),
	}).
		Assign(common.TokenData{
			RequesterID: tokenRequest.RequesterID,
			DeviceID:    tokenRequest.DeviceID,
			Country:     tokenRequest.Country,
			Type:        strings.ToLower(tokenRequest.Type),
			JTI:         jti,
			ExpiresAt:   refreshTokenExpiry,
		}).FirstOrCreate(&refreshToken)

	if result.Error != nil {
		fmt.Println(result.Error)
		fmt.Printf("Error: %v\n", result.Error)
		redisErr := RemoveKeyFromRedis(&jti, 0)
		if redisErr != nil {
			return nil, redisErr
		}
		return nil, result.Error
	}

	/*if result.RowsAffected > 0 {
		fmt.Printf("%d rows were affected.\n", result.RowsAffected)
	}*/

	returnData := common.TokenReturnData{
		Type:         refreshToken.Type,
		Payload:      tokenRequest.Payload,
		AccessToken:  generatedAccessToken,
		ExpiresAt:    accessTokenExpiry,
		RefreshToken: generatedRefreshToken,
		RtExpiresAt:  refreshTokenExpiry,
	}

	return &returnData, nil

}

// GenerateJWT generates a JWT with custom claims and signs it with a private key.
func GenerateJWT(claims jwt.Claims) (string, error) {

	/*privateKeyPath := "./private_key.pem"
	// Load your private key from a file or any other source.
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}*/
	privateKeyBytes := *PrivateKeyContent

	// Parse the private key and create a signing key function.
	privateKey, err := jwt.ParseECPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", err
	}

	// Create a new token.
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign the token with the private key.
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func VerifyJWT(tokenString *string) (jwt.MapClaims, error) {
	// Load your public key from a file or any other source.
	publicKeyPath := "./public_key.pem"
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	// Parse the public key and create a verification key function.
	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	// Parse and verify the token.
	token, err := jwt.Parse(*tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	/*if err != nil {

		return nil, err
	}
	*/
	if token.Valid {
		// Return the token's claims if verification succeeds
		claims, _ := token.Claims.(jwt.MapClaims)
		/*if !ok {
			return nil, errors.New("invalid token claims")
		}*/
		return claims, nil
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		return nil, errors.New("malformed token")
	} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
		// Token is either expired or not active yet
		return nil, errors.New("expired")
	} else {
		return nil, errors.New("invalid token")
	}

}

// GetTokenStructLevelValidation contains custom struct level validations that don't always
// make sense at the field validation level. For Example this function validates that either
// FirstName or LastName exist; could have done that with a custom field validation but then
// would have had to add it to both fields duplicating the logic + overhead, this way it's
// only validated once.
//
// NOTE: you may ask why wouldn't I just do this outside of custom_validator, because doing this way
// hooks right into custom_validator and you can combine with validation tags and still have a
// common error output format.

/*func GetTokenStructLevelValidation(sl custom_validator.StructLevel) {

	user := sl.Current().Interface().(User)

	if len(user.FirstName) == 0 && len(user.LastName) == 0 {
		sl.ReportError(user.FirstName, "fname", "FirstName", "fnameorlname", "")
		sl.ReportError(user.LastName, "lname", "LastName", "fnameorlname", "")
	}

	// plus can do more, even with different tag than "fnameorlname"
}*/

func StoreAccessTokenToRedis(key *string, tokenRequest *common.TokenRequest, expiryInSeconds int64) bool {
	/*val, err := redisClient.Get(database.Ctx, "key").Result()
	switch {
	case err == redis.Nil:
		fmt.Println("key does not exist")
	case err != nil:
		fmt.Println("Get failed", err)
	case val == "":
		fmt.Println("value is empty")
	}*/

	//expiration := 30 * 24 * 60 * 60 * time.Second

	redisTtl := time.Duration(expiryInSeconds) * time.Second

	jsonData := map[string]interface{}{
		"device_id":    tokenRequest.DeviceID,
		"requester_id": tokenRequest.RequesterID,
		"payload":      tokenRequest.Payload,
		"country":      tokenRequest.Country,
		"provider":     tokenRequest.Provider,
	}

	// Convert the JSON data to a string
	jsonStr, err := json.Marshal(jsonData)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
	}

	err = redis.Client0.Set(database.Ctx, *key, jsonStr, redisTtl).Err()
	if err != nil {
		fmt.Println("Error setting value in Redis:", err)
		return false
	}

	// Retrieve the value from Redis
	/*val, err := rdb.Get(context.Background(), "jti").Result()
	if err != nil {
		fmt.Println("Error getting value from Redis:", err)
		return
	}

	// Print the retrieved value
	fmt.Println("Retrieved JSON string:", val)

	// Parse the JSON string back to a map
	var retrievedData map[string]interface{}
	if err := json.Unmarshal([]byte(val), &retrievedData); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	// Print the retrieved JSON data
	fmt.Println("Retrieved JSON data:", retrievedData)*/

	return true
}

func RemoveKeyFromRedis(key *string, dbNo int) error {

	var delCmd *goRedis.IntCmd

	if dbNo == 0 {
		delCmd = redis.Client0.Del(database.Ctx, *key)
	} else {
		delCmd = redis.Client1.Del(database.Ctx, *key)
	}

	if delCmd.Err() != nil {
		fmt.Println("Error deleting key:", delCmd.Err())
		return errors.New("something went wrong")
	}

	return nil

	// Check if the key was deleted
	/*if delCmd.Val() == 1 {
		fmt.Println("Key deleted successfully")
	} else {
		fmt.Println("Key does not exist")
	}*/

}

func GenerateUniqueJTI() string {
	// Generate a new UUID (v4)
	id := uuid.New()

	// Get the current Unix epoch time in milliseconds
	epochTime := time.Now().Unix()

	// Concatenate UUID string and epoch time
	uniqueJTI := id.String() + "_" + strconv.FormatInt(epochTime, 10)

	return uniqueJTI
}

func CheckIfJtiExistsInDB(claims *jwt.MapClaims) (*model.RefreshToken, error) {
	db := database.DB.Db
	var refreshToken model.RefreshToken

	claimsVal := *claims

	result := db.Where(&model.RefreshToken{
		Type: claimsVal["type"].(string),
		JTI:  claimsVal["jti"].(string),
	}).First(&refreshToken)

	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
		return nil, result.Error
	}

	return &refreshToken, nil
}

func DeleteIfExistsInRedis(key *string) error {
	// Check if key exists
	exists := redis.Client0.Exists(database.Ctx, *key)
	if exists.Val() == 1 {
		// Key exists, delete it
		status := redis.Client0.Del(database.Ctx, *key)
		if status.Err() != nil {
			return errors.New("something went wrong")
		}
	} else {
		return errors.New("invalid token")
	}
	return nil
}

func DeleteIfExistsInDB(claims *jwt.MapClaims) error {
	db := database.DB.Db
	claimsVal := *claims

	result := db.Where(&model.RefreshToken{
		Type: claimsVal["type"].(string),
		JTI:  claimsVal["jti"].(string),
	}).Delete(&model.RefreshToken{})

	if result.Error != nil {
		return result.Error // Return the encountered error
	}

	/*if result.RowsAffected == 0 {
		fmt.Println("Record not found")
		return nil // Return nil as the record doesn't exist
	}*/

	return nil // Return nil for successful deletion
}

func CheckIfExistsInRedis(key *string) (*common.AccessTokenRedisData, error) {

	data, err := redis.Client0.Get(database.Ctx, *key).Result()

	if err == goRedis.Nil {
		return nil, errors.New("key_does_not_exist")
	} else if err != nil {
		return nil, errors.New("something went wrong while fetching value from redis")
	} else {
		var redisData common.AccessTokenRedisData
		err = json.Unmarshal([]byte(data), &redisData)
		if err != nil {
			fmt.Println(errors.New("error decoding redis data"))
		}
		return &redisData, nil
	}

}

var PrivateKeyContent *[]byte
var PublicKeyContent *[]byte

func LoadPublicKey() {
	// Load your public key from a file or any other source.
	publicKeyPath := "./public_key.pem"

	// Load your private key from a file or any other source.
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log := logger.GetForFile("startup-errors")
		log.Error("Could not load public key", zap.Error(err))
	}
	// Store the content as a pointer to the global variable
	PublicKeyContent = &publicKeyBytes
}

func LoadPrivateKey() {
	privateKeyPath := "./private_key.pem"

	// Load your private key from a file or any other source.
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log := logger.GetForFile("startup-errors")
		log.Error("Could not load private key", zap.Error(err))
	}

	// Store the content as a pointer to the global variable
	PrivateKeyContent = &privateKeyBytes
}

func GetTokenFromHeader(authorizationHeader *string) (*string, error) {
	// Split the header by whitespace (" ")
	headerParts := strings.Split(*authorizationHeader, " ")

	// Check if it has two parts and the first part is "Bearer"
	if len(headerParts) == 2 && headerParts[0] == "Bearer" {
		// Extract the token part
		*authorizationHeader = headerParts[1]
	} else {
		return nil, errors.New("invalid authorization header")
	}
	return authorizationHeader, nil
}

func GetRefreshTokenAgainstJti(jti *string, tokenType *string) (*model.RefreshToken, error) {
	db := database.DB.Db
	var refreshToken model.RefreshToken

	result := db.Where(&model.RefreshToken{
		Type: *tokenType,
		JTI:  *jti,
	}).First(&refreshToken)

	if result.Error != nil {
		return nil, result.Error
	}
	return &refreshToken, nil
}
