package model

type RefreshToken struct {
	BaseModel   BaseModel `gorm:"embedded"`
	Type        string    `gorm:"uniqueIndex:idx_type_requester_device"`
	DeviceID    string    `gorm:"uniqueIndex:idx_type_requester_device"`
	RequesterID string    `gorm:"uniqueIndex:idx_type_requester_device"`
	Provider    string    `gorm:"not null;default:'toffee'"`
	Country     string    `gorm:"not null;default:'BD'"`
	ExpiresAt   int64     `gorm:"not null"`
	JTI         string    `gorm:"not null;column:jti"`
}
