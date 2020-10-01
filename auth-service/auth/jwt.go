package auth

import (
	"log"
	"time"
	"errors"
	"crypto/rsa"
	"io/ioutil"
	"github.com/dgrijalva/jwt-go"
)

var (
	DefaultAccessJWTExpiry  = 01 * 1440 * time.Minute // refresh every 01 days
	DefaultRefreshJWTExpiry = 30 * 1440 * time.Minute // refresh every 30 days
	defaultJWTIssuer = "auth-service"
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
)

func init() {

	privateBytes, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Fatal(err.Error())
	}

	publicBytes,  err := ioutil.ReadFile("public.pem")
	if err != nil {
		log.Fatal(err.Error())
	}

	publicKey,  err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Fatal(err.Error())
	}

}

type AuthClaims struct {
	Email string
	EmailVerified bool
	UserId string
	jwt.StandardClaims
}

func setClaims(claims AuthClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func getClaims(tokenString string) (claims AuthClaims, Error error) {
	claims = AuthClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return AuthClaims{}, err
	}
	if !token.Valid	{
		return AuthClaims{}, errors.New("The given token is not valid.")
	}
	return claims, nil	
}
