package auth

import (
	"time"
	"errors"
	"github.com/dgrijalva/jwt-go"
)

var (
	DefaultAccessJWTExpiry  =  5        * time.Minute // refresh every  5 minutes
	DefaultRefreshJWTExpiry = 30 * 1440 * time.Minute // refresh every 30 days
	defaultJWTIssuer        = "workspace-api"
	jwtKey                  = []byte("my_secret_key")
)

func setClaims(data map[string]interface{}) (tokenString string, Error error) {
	claims := jwt.StandardClaims{
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

func getClaims(tokenString string) (data map[string]interface{}, Error error) {
	claims := jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid	{
		return nil, errors.New("The given token is not valid")
	}
	return claims, nil	
}
