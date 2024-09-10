package model

import "time"

type BaseModel struct {
	ID        int64 `gorm:"primaryKey;autoIncrement"`
	CreatedAt time.Time
	UpdatedAt time.Time
	// Exclude DeletedAt
}
