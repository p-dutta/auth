package common

import (
	"github.com/google/uuid"
	"time"
)

type PolicyRequest struct {
	Type     string `json:"type" validate:"required,policy_type_custom_validation"`
	AtExpiry int64  `json:"at_duration" validate:"required,numeric"`
	RtExpiry int64  `json:"rt_duration" validate:"required,numeric"`
	Iss      string `json:"iss" validate:"required"`
}

type PolicyReturnData struct {
	ID        uuid.UUID `json:"id"`
	Type      string    `json:"type"`
	AtExpiry  int64     `json:"at_duration"`
	RtExpiry  int64     `json:"rt_duration"`
	Iss       string    `json:"iss"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
