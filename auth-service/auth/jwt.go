package auth

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"time"
)

var (
	DefaultAccessJWTExpiry  =  5        * time.Minute // refresh every  5 minutes
	DefaultRefreshJWTExpiry = 30 * 1440 * time.Minute // refresh every 30 days
	defaultJWTIssuer        = "workspace-api"
	jwtKey                  = []byte("my_secret_key")
)

func NewClaims(data map[string]interface{}) (string, error) {

	claims := jwt.MapClaims{
		"Issuer":    defaultJWTIssuer,
		"IssuedAt":  time.Now().Unix(),
	}

	for key, val := range data {
    claims[key] = val
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, err
}

func ExtractToken(r *http.Request, tokenName string) (string, error) {
	c, err := r.Cookie(tokenName)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	// do something with decoded claims
	for key, val := range claims {
		// fmt.Printf("Key: %v, value: %v\n", key, val)
	}

	return token, nil
}

func ValidateToken(token *jwt.Token) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.MapClaims); !ok && !token.Valid {
		return err
	}
	return nil
}