package database

import (
	"auth/common"
	"auth/logger"
	"auth/model"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ConnectDB connect to db
func ConnectDB() {
	var err error
	//p := config.Config("DB_PORT")
	p := os.Getenv("DB_PORT")
	port, err := strconv.ParseUint(p, 10, 32)

	if err != nil {
		panic("failed to parse database port")
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		port,
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	/*dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		port,
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)*/

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		//Logger: logger.Default.LogMode(logger.Info),
	})

	if err != nil {
		log := logger.GetForFile("startup-errors")
		log.Error("Error while connecting to database",
			zap.Error(err),
		)
		panic("failed to connect to database")
	}

	// Set connection pool settings
	sqlDB, err := db.DB()
	if err != nil {
		panic("failed to get database instance")
	}

	sqlDB.SetMaxIdleConns(10)           // Set the maximum number of connections in the idle connection pool.
	sqlDB.SetMaxOpenConns(100)          // Set the maximum number of open connections to the database.
	sqlDB.SetConnMaxLifetime(time.Hour) // Set the maximum amount of time a connection may be reused.

	fmt.Println("Connection Opened to Database")

	// List of model structs
	models := []interface{}{
		&model.RefreshToken{},
		&model.Policy{},
		&model.GrantType{},
		// Add the rest of your model structs here (ModelC, ModelD, ..., ModelJ)
	}

	// List of your model structs
	// Loop through your models and apply AutoMigrate
	for _, individualModel := range models {
		if err := db.AutoMigrate(individualModel); err != nil {
			panic("Failed to create table: " + err.Error())
		}
	}

	fmt.Println("Database Migrated")

	// Check if any grant type exist
	var countGrantType int64
	if err := db.Model(&model.GrantType{}).Count(&countGrantType).Error; err != nil {
		log := logger.GetForFile("startup-errors")
		log.Error("Error while getting the count of grant types",
			zap.Error(err),
		)
	}

	if countGrantType == 0 {
		// If no policies exist, insert a default policy
		defaultGrantType := &model.GrantType{
			Name:        common.SuperAdmin,
			Description: "super admin",
		}
		if err := db.Create(defaultGrantType).Error; err != nil {
			log := logger.GetForFile("startup-errors")
			log.Error("Error creating default policy",
				zap.Error(err),
			)
		}
		fmt.Println("Default grant type inserted successfully.")
	}

	// Check if any policies exist
	var countPolicy int64
	if err := db.Model(&model.Policy{}).Count(&countPolicy).Error; err != nil {
		log := logger.GetForFile("startup-errors")
		log.Error("Error while getting the count of policies",
			zap.Error(err),
		)
	}

	adminAtExpiryStr := os.Getenv("ADMIN_AT_EXPIRY")
	adminRtExpiryStr := os.Getenv("ADMIN_RT_EXPIRY")

	adminAtExpiry, _ := strconv.ParseInt(adminAtExpiryStr, 10, 64)
	adminRtExpiry, _ := strconv.ParseInt(adminRtExpiryStr, 10, 64)

	if countPolicy == 0 {
		// If no policies exist, insert a default policy
		defaultPolicy := &model.Policy{
			Type:     common.SuperAdmin,
			AtExpiry: adminAtExpiry,
			RtExpiry: adminRtExpiry,
			Iss:      "toffeelive.com",
		}
		if err := db.Create(defaultPolicy).Error; err != nil {
			log := logger.GetForFile("startup-errors")
			log.Error("Error creating default policy",
				zap.Error(err),
			)
		}
		fmt.Println("Default policy inserted successfully.")
	}

	DB = DbInstance{
		Db: db,
	}
}

//var Ctx = context.Background()

func CreateRedisClient(dbNo int) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASS"),
		DB:       dbNo,
	})
	return rdb
}

func CloseRedisClient(client *redis.Client) {
	err := client.Close()
	if err != nil {
		fmt.Println("Failed to close Redis client.")
	}
}
