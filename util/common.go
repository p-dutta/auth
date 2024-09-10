package util

import "regexp"

func ValidateUUIDv4(id string) bool {
	uuidV4Regex := regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	return uuidV4Regex.MatchString(id)
}
