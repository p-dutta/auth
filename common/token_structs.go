package common

import (
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

//type TokenType uint

/*func (tokenType TokenType) String() string {
	terms := []string{"subscriber", "device", "admin", "partner", "service"}
	if tokenType < Subscriber || tokenType > Service {
		return "-1"
	}
	return terms[tokenType-1]
}*/

type TokenRequest struct {
	//Type           string `json:"type" validate:"required,grant_type_custom_validation"`
	Type           string `json:"type" validate:"required"`
	DeviceID       string `json:"device_id" validate:"required"`
	RequesterID    string `json:"requester_id" validate:"required,uuid4"`
	Provider       string `json:"provider" validate:"required"`
	Payload        string `json:"payload"`
	Country        string `json:"country" validate:"required"`
	AccessTokenExp int64  `json:"at_duration" validate:"omitempty,numeric"`
	//RefreshTokenExp int64  `json:"rt_duration" validate:"validate_rt_duration"`
	RefreshTokenExp int64 `json:"rt_duration"`
}

type TokenData struct {
	Type        string
	RequesterID string
	DeviceID    string
	Country     string
	ExpiresAt   int64
	JTI         string
}

type TokenReturnData struct {
	Type         string `json:"type"`
	Payload      string `json:"payload"`
	AccessToken  string `json:"access_token"`
	ExpiresAt    int64  `json:"at_expires_at"`
	RefreshToken string `json:"refresh_token"`
	RtExpiresAt  int64  `json:"rt_expires_at"`
}

type TokenResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	//Data    interface{} `json:"data"`
	Data TokenReturnData `json:"data"`
}

type IError struct {
	Field string
	Tag   string
	Value interface{}
}

type CustomClaims struct {
	RequesterID string `json:"requester_id"`
	DeviceID    string `json:"device_id"`
	jwt.RegisteredClaims
}

type ValidateTokenReturnData struct {
	Type        string  `json:"type"`
	Token       string  `json:"token"`
	Jti         string  `json:"jti"`
	Iat         float64 `json:"iat"`
	Exp         float64 `json:"exp"`
	Iss         string  `json:"iss"`
	RequesterID string  `json:"requester_id"`
	DeviceID    string  `json:"device_id"`
	Provider    string  `json:"provider"`
	Country     string  `json:"country"`
}

type AccessTokenRedisData struct {
	RequesterID string `json:"requester_id"`
	DeviceID    string `json:"device_id"`
	Provider    string `json:"provider"`
	Country     string `json:"country"`
}

type TokenClaims struct {
	Aud   string `json:"aud"`
	Exp   int    `json:"exp"`
	Iat   int    `json:"iat"`
	Iss   string `json:"iss"`
	Jti   string `json:"jti"`
	Token string `json:"token"`
	Type  string `json:"type"`
}
