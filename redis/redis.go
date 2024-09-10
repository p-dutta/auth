package redis

import (
	"auth/database"
	"fmt"
	"github.com/redis/go-redis/v9"
	"os"
)

var Client0 *redis.Client
var Client1 *redis.Client

func InitRedis() {
	Client0 = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASS"),
		DB:       0,
	})

	Client1 = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASS"),
		DB:       1,
	})

}

func CloseRedisClient() error {
	if Client0 != nil {
		return Client0.Close()
	}
	if Client1 != nil {
		return Client1.Close()
	}

	return nil
}

func PingRedis() error {
	pong, err := Client0.Ping(database.Ctx).Result()
	if err != nil {
		return err
	}
	fmt.Println(pong)
	return nil
}
