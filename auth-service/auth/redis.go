package auth 

import (
	"time"
	"encoding/json"
	"github.com/gomodule/redigo/redis"
)

type RevokedItem struct {
	invalid bool // refresh token
	stale string // jwt token
}

// Declare a pool variable to hold the pool of Redis connections.
var pool *redis.Pool

func init() {
	pool = &redis.Pool{MaxIdle: 10, IdleTimeout: 240 * time.Second, 
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", "localhost")
		},
	}
}

func RevokedItemExpiry(val RevokedItem) time.Duration {
	if val.invalid {
		return DefaultRefreshJWTExpiry
	} else {
		return DefaultAccessJWTExpiry
	}
}

func getRevokedItem(key string, val RevokedItem) error {
	// Fetch redis connection from pool and close after function exit.
	conn := pool.Get()
	defer conn.Close()

	resp, err := conn.Do("GET", key)
	if err != nil {
		return err
	}
	return json.Unmarshal(resp.([]byte), val)
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

