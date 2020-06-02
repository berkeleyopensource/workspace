package auth 

import (
	"time"
	"encoding/json"
	"github.com/gomodule/redigo/redis"
)

type RevokedItem struct {
	InvalidIssuedAt int64 // unix timestamp of when Invalid was issued
	Invalid bool // used to invalidate all refreshTokens before InvalidIssuedAt
	NewClaimsIssuedAt int64 // unix timestamp of when NewClaims was issued
	NewClaims string // used to update all accessTokens before NewClaimsIssuedAt
}

func RevokedItemExpiry(val RevokedItem) int64 {
	var invalidExpiry, claimsExpiry int64;
	if (val.Invalid != false) {
		// Calculate remaining expiry for invalid field.
		invalidExpiry = int64(DefaultRefreshJWTExpiry.Seconds()) + val.InvalidIssuedAt - time.Now().Unix()
	}
	if (val.NewClaims != "") {
		// Calculate remaining expiry for claims field.
		claimsExpiry = int64(DefaultAccessJWTExpiry.Seconds()) + val.NewClaimsIssuedAt - time.Now().Unix()
	}
	// Return the maximum of invalid and claims expiry.
	if claimsExpiry < invalidExpiry {
		return invalidExpiry
	} else {
		return claimsExpiry
	}
}

// Declare a pool variable to hold the pool of Redis connections.
var pool *redis.Pool

func init() {
	pool = &redis.Pool{MaxIdle: 10, IdleTimeout: 240 * time.Second, 
		Dial: func() (redis.Conn, error) {
			conn, err := redis.Dial("tcp", "redis:6379")
			// Exponential backoff if unsuccessful connection.
			for retries := 0; err != nil && retries < 5; retries++ {
				time.Sleep((50 << retries) * time.Millisecond)
				conn, err = redis.Dial("tcp", "redis:6379")
			}
			return conn, err
		},
	}
}

func getRevokedItem(key string, val RevokedItem) error {
	// Fetch redis connection from pool and close after function exit.
	conn := pool.Get()
	defer conn.Close()

	var resp []byte
	resp, err := redis.Bytes(conn.Do("GET", key))
	if err == redis.ErrNil {
		return nil // Can't unmarshal nil resp so return unmodified val.
	} else if err != nil {
		return err
	}
	return json.Unmarshal(resp, &val)
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

