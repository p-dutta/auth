package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

//default:uuid_generate_v4()
type GrantType struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey;"`
	Name        string    `gorm:"column:name"`
	Description string    `gorm:"column:description"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt
}

// BeforeCreate callback to generate a UUID before creating a new record
func (grantType *GrantType) BeforeCreate(tx *gorm.DB) (err error) {
	if grantType.ID == uuid.Nil {
		grantType.ID = uuid.New()
	}
	return
}
