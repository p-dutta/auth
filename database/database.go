package database

import (
	"context"
	"gorm.io/gorm"
)

type DbInstance struct {
	Db *gorm.DB
}

// DB gorm connector
var DB DbInstance

var Ctx = context.Background()

/*// Set a timeout for the Redis operation (e.g., 5 seconds)
var timeout = 5 * time.Second

// Create a context with a timeout
ctx, cancel := context.WithTimeout(Ctx, timeout)
defer cancel()*/
