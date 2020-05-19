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

func ExtractToken(r *http.Request, tokenName string) (string, int, error) {
	c, err := r.Cookie(tokenName)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", http.StatusUnauthorized, errors.New("No refresh token found").Error()
		}
		return "", http.StatusBadRequest, errors.New("Bad Request").Error()
	}

	return c.Value, nil, -1
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
		fmt.Printf("Key: %v, value: %v\n", key, val)
	}

	return token, nil
}

func Validatetoken(token *jwt.Token) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.MapClaims); !ok && !token.Valid {
		return err
	}
	return nil
}
