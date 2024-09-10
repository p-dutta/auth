package main

import (
	"auth/database"
	"auth/logger"
	"auth/middleware"
	"auth/redis"
	"auth/router"
	"auth/util"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

func init() {
	// Loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log := logger.GetForFile("startup-errors")
		log.Error("No .env file found", zap.Error(err))
	}

	util.LoadPrivateKey()
	util.LoadPublicKey()

	redis.InitRedis()

}

func main() {
	app := fiber.New(fiber.Config{
		CaseSensitive: true,
		StrictRouting: true,
		AppName:       "Toffee Auth",
	})

	//app.Use(cors.New())

	app.Use(cors.New(cors.Config{
		AllowHeaders:     "Origin,Content-Type,Accept,Content-Length,Accept-Language,Accept-Encoding,Connection,Access-Control-Allow-Origin,Authorization",
		AllowOrigins:     "*",
		AllowCredentials: true,
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
	}))

	app.Use(helmet.New())
	//app.Use(csrf.New())
	app.Use(middleware.RecoverFromPanic)

	database.ConnectDB()

	if err := redis.PingRedis(); err != nil {
		// Handle error if Redis connection fails
		log := logger.GetForFile("startup-errors")
		log.Error("Failed to ping Redis client", zap.Error(err))
	}

	/*redisClient := database.CreateRedisClient(0)
	if redisClient == nil {
		log := logger.GetForFile("startup-errors")
		log.Error("Failed to initialize Redis client")

		return
	}
	_, err := redisClient.Ping(database.Ctx).Result()
	if err != nil {
		fmt.Println("Failed to connect to Redis:", err)
	}
	fmt.Println("Pinged redis successfully..")*/

	//defer redisClient.Close()

	/*defer func(redisClient *redis.Client) {
		err := redisClient.Close()
		if err != nil {
			fmt.Println("Failed to close Redis client.")
		}
	}(redisClient)*/

	defer func() {
		err := redis.CloseRedisClient()
		if err != nil {
			log := logger.GetForFile("startup-errors")
			log.Error("Failed to close Redis client", zap.Error(err))
		}
	}()

	router.SetupRoutes(app)

	if err := app.Listen(":" + os.Getenv("APP_PORT")); err != nil {
		log := logger.GetForFile("startup-errors")
		log.Error("Failed to start server", zap.Error(err))
	}

}
