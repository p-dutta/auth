package util

import (
	"auth/common"
	"auth/database"
	"auth/model"
	"auth/redis"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

func GetPolicyData() (*[]common.PolicyReturnData, error) {

	key := common.PolicyRedisKey
	var policyData []common.PolicyReturnData

	// Check if the key exists in Redis
	data, err := redis.Client1.Get(database.Ctx, key).Result()

	if err == nil {
		err = json.Unmarshal([]byte(data), &policyData)
		if err != nil {
			fmt.Println(errors.New("error decoding redis data"))
		}
	} else {

		db := database.DB.Db

		var policies []model.Policy

		result := db.Find(&policies)

		if result.Error != nil {
			return nil, result.Error
		} else if result.RowsAffected == 0 {
			return nil, errors.New("no policy found")
		}

		for _, p := range policies {
			prd := common.PolicyReturnData{
				ID:        p.ID,
				Type:      p.Type,
				AtExpiry:  p.AtExpiry,
				RtExpiry:  p.RtExpiry,
				Iss:       p.Iss,
				CreatedAt: p.CreatedAt,
				UpdatedAt: p.UpdatedAt,
			}
			policyData = append(policyData, prd)
		}

		redisData, err := json.Marshal(policyData)
		if err != nil {
			fmt.Println(errors.New("error while encoding policy to json"))
		}
		err = redis.Client1.Set(database.Ctx, key, redisData, 24*time.Hour).Err()
		if err != nil {
			fmt.Println("Error setting value in Redis:", err)
			return nil, errors.New("error setting policy to redis")
		}

	}

	return &policyData, nil

}
