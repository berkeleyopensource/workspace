package auth

import (
	"time"
	"errors"
	"github.com/dgrijalva/jwt-go"
)

var (
	DefaultAccessJWTExpiry  = 01 * 1440 * time.Minute // refresh every 01 days
	DefaultRefreshJWTExpiry = 30 * 1440 * time.Minute // refresh every 30 days
	defaultJWTIssuer        = "workspace-api"
	jwtKey                  = []byte("my_secret_key")
)

type AuthClaims struct {
	Email string
	EmailVerified bool
	UserId string
	jwt.StandardClaims
}

func setClaims(claims AuthClaims) (tokenString string, Error error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, err
}

func getClaims(tokenString string) (claims AuthClaims, Error error) {
	claims = AuthClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return AuthClaims{}, err
	}
	if !token.Valid	{
		return AuthClaims{}, errors.New("The given token is not valid")
	}
	return claims, nil	
}
