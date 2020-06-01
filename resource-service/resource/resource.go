package resource

import (
	"log"
	"time"
	"net/http"
	"errors"
	"database/sql"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// Checks that refreshToken is valid and accessToken is not stale.
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		refreshCookie, err := r.Cookie("refresh_token")
		if err != nil {
			if (err == http.ErrNoCookie) {
				http.Error(w, err.Error(), http.StatusUnauthorized)
			} else {
				http.Error(w, errors.New("Error retrieving refreshToken.").Error(), http.StatusInternalServerError)
			}
			return
		}
	
		claims, err := getClaims(refreshCookie.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	
		// Check if refreshToken has been revoked and invalidated.
		var revoked RevokedItem
		err = getRevokedItem(claims.UserId, revoked)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	
		// Clear cookies if refreshToken has been revoked.
		if (revoked != RevokedItem{} && revoked.Invalid == true && claims.StandardClaims.IssuedAt < revoked.InvalidIssuedAt) {
			var expiresAt = time.Now().Add(-1 * time.Second)
			http.SetCookie(w, &http.Cookie{ Name: "access_token",  Value: "", Expires: expiresAt})
			http.SetCookie(w, &http.Cookie{ Name: "refresh_token", Value: "", Expires: expiresAt})
			http.Error(w, errors.New("The refreshToken has been revoked.").Error(), http.StatusUnauthorized)
			return		
		}
	
		accessCookie, err := r.Cookie("access_token")
		if err != nil {
			if (err == http.ErrNoCookie) {
				http.Error(w, errors.New("Error there is no cookie.").Error(), http.StatusUnauthorized)
			} else {
				http.Error(w, errors.New("Error retrieving accessToken.").Error(), http.StatusInternalServerError)
			}
			return
		}
	
		// Check if accessToken has stale claims that can be updated from cache.
		oldAccessToken := accessCookie.Value
		if (revoked != RevokedItem{} && revoked.NewClaims != "" && claims.StandardClaims.IssuedAt < revoked.NewClaimsIssuedAt) {
			oldAccessToken = revoked.NewClaims
		}
	
		claims, err = getClaims(oldAccessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	
		// Update expiration time of accessToken claims.
		var accessExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
		claims.StandardClaims.ExpiresAt = accessExpiresAt.Unix()
	
		// Set access token as a cookie.
		var accessToken string
		accessToken, err = setClaims(claims)
		if err != nil {
			http.Error(w, errors.New("Error creating accessToken.").Error(), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "access_token",
			Value: accessToken,
			Expires: accessExpiresAt,
		})
	
		next.ServeHTTP(w, r)
	})
}

func RegisterRoutes(router *mux.Router) error {
	return nil
}