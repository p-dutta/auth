package custom_validator

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/go-playground/validator/v10"
)

// CustomValidator is a custom custom_validator for handling custom validation logic
var CustomValidator *validator.Validate

func init() {
	CustomValidator = validator.New()
	/*err := CustomValidator.RegisterValidation("grant_type_custom_validation", tokenTypeCustomValidation)
	err = CustomValidator.RegisterValidation("validate_token_exp", validateRefreshTokenExp)
	if err != nil {
		fmt.Println(err)
	}*/

	if err := CustomValidator.RegisterValidation("grant_type_custom_validation", tokenTypeCustomValidation); err != nil {
		fmt.Println("failed to register grant_type_custom_validation")
	}

	if err := CustomValidator.RegisterValidation("validate_rt_duration", validateRefreshTokenExp); err != nil {
		fmt.Println("failed to register validate_token_exp")
	}

	//CustomValidator.RegisterStructValidation(TokenRequestStructLevelValidation, common.TokenRequest{})

}

func validateRefreshTokenExp(fl validator.FieldLevel) bool {
	accessTokenExp := fl.Parent().FieldByName("AccessTokenExp")
	refreshTokenExp := fl.Parent().FieldByName("RefreshTokenExp")

	if accessTokenExp.IsZero() && refreshTokenExp.IsZero() {
		return true
	}

	return !refreshTokenExp.IsZero() && refreshTokenExp.Kind() == reflect.Int64 &&
		!accessTokenExp.IsZero() && accessTokenExp.Kind() == reflect.Int64
}

func tokenTypeCustomValidation(fl validator.FieldLevel) bool {
	//log.Println("from token type validation............")
	tokenTypeVal := fl.Field()

	//fmt.Println("Type of variable1:", reflect.TypeOf(value.String()))

	//fmt.Printf("Value: %+v\n", value)

	envTokenTypeStr := os.Getenv("GRANT_TYPES")

	if envTokenTypeStr == "" {
		fmt.Println("Environment variable not set")
	}

	// Split the environment variable value into a slice
	tokenTypeSlice := strings.Split(envTokenTypeStr, ",")

	return slices.Contains(tokenTypeSlice, strings.ToLower(tokenTypeVal.String()))
}

/*func TokenRequestStructLevelValidation(sl validator.StructLevel) {

	tokenRequest := sl.Current().Interface().(common.TokenRequest)

	fmt.Printf("%+v\n", tokenRequest)
	//fmt.Println(tokenRequest)

	fmt.Println(tokenRequest.RefreshTokenExp)

}*/
