package model

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

//default:uuid_generate_v4()
type Policy struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;"`
	Type      string    `gorm:"column:type"`
	AtExpiry  int64     `gorm:"column:at_duration"`
	RtExpiry  int64     `gorm:"column:rt_duration"`
	Iss       string    `gorm:"column:iss"`
	CreatedAt time.Time
	UpdatedAt time.Time
	//DeletedAt time.Time
	DeletedAt gorm.DeletedAt
}

// BeforeCreate callback to generate a UUID before creating a new record
func (policy *Policy) BeforeCreate(tx *gorm.DB) (err error) {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}
	return
}
