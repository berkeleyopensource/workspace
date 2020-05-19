package auth

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

var (
	DefaultAccessJWTExpiry  = 5 * time.Minute
	DefaultRefreshJWTExpiry = 30 * time.Day
	defaultJWTIssuer        = "workspace-api"
	jwtKey                  = []byte("my_secret_key")
)

func NewClaim(email, subject string, verified bool) (string, error) {

	var expirationTime time.Time
	if subject == "access" {
		expirationTime = time.Now().Add(defaultAccessJWTExpiry)
	} else {
		expirationTime = time.Now().Add(defaultRefreshJWTExpiry)
	}

	claim := jwt.MapClaims{
		"iss":            defaultJWTIssuer,
		"sub":            subject,
		"iat":            time.Now().Unix(),
		"exp":            expirationTime.Unix(),
		"email":          email,
		"email_verified": verified,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, err
}
