package custom_validator

import (
	"auth/config"
	"fmt"
	"slices"
	"strings"

	"github.com/go-playground/validator/v10"
)

var PolicyValidator *validator.Validate

func init() {
	PolicyValidator = validator.New()

	if err := PolicyValidator.RegisterValidation("policy_type_custom_validation", policyTypeCustomValidation); err != nil {
		fmt.Println("failed to register policy_type_custom_validation")
	}

}

func policyTypeCustomValidation(fl validator.FieldLevel) bool {
	policyTypeVal := fl.Field()

	envPolicyTypeStr := config.Config("POLICY_TYPES")

	if envPolicyTypeStr == "" {
		fmt.Println("POLICY_TYPES env is not set")
	}

	policyTypeSlice := strings.Split(envPolicyTypeStr, ",")

	return slices.Contains(policyTypeSlice, strings.ToLower(policyTypeVal.String()))
}
