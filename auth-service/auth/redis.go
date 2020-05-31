package auth 

import (
	"time"
	"encoding/json"
	"github.com/gomodule/redigo/redis"
)

type RevokedItem struct {
	IssuedAt int64 // unix timestamp of when RevokedItem was issued
	Invalid bool // used to invalidate all refreshTokens before IssuedAt
	NewClaims string // used to update all accessTokens before IssuedAt
}


// Declare a pool variable to hold the pool of Redis connections.
var pool *redis.Pool

func init() {
	pool = &redis.Pool{MaxIdle: 10, IdleTimeout: 240 * time.Second, 
		Dial: func() (redis.Conn, error) {
			conn, err := redis.Dial("tcp", "localhost:6379")
			// Exponential backoff if unsuccessful connection.
			for retries := 0; err != nil && retries < 5; retries++ {
				time.Sleep((50 << retries) * time.Millisecond)
				conn, err = redis.Dial("tcp", "localhost:6379")
			}
			return conn, err
		},
	}
}

func RevokedItemExpiry(val RevokedItem) int {
	if val.Invalid {
		return int((DefaultRefreshJWTExpiry).Round(time.Second).Seconds())
	} else {
		return int((DefaultAccessJWTExpiry).Round(time.Second).Seconds())
	}
}

func getRevokedItem(key string, val RevokedItem) error {
	// Fetch redis connection from pool and close after function exit.
	conn := pool.Get()
	defer conn.Close()

	resp, err := redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return err
	}
	return json.Unmarshal(resp, val)
}

func setRevokedItem(key string, val RevokedItem) error {
	// Fetch redis connection from pool and close after function exit.
	conn := pool.Get()
	defer conn.Close()

	resp, err := json.Marshal(val)
	if err != nil {
		return err
	}
	_, err = conn.Do("SETEX", key, RevokedItemExpiry(val), resp)
	return err
}

