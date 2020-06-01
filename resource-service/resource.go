package auth

import (
	"log"
	"time"
	"net/http"
	"math/rand"
	"errors"
	"encoding/json"
	"crypto/sha256"
	"database/sql"
	"golang.org/x/crypto/bcrypt"
	"github.com/google/uuid"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

const (
	tokenSize = 8;
)

func getRandomBase62(length int) string {
	const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	rand.Seed(time.Now().Unix())
	r := make([]byte, length)
	for i := range r {
		r[i] = base62[rand.Intn(len(base62))]
	}
	return string(r)
}

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
		if (revoked != RevokedItem{} && claims.StandardClaims.IssuedAt < revoked.IssuedAt && revoked.Invalid == true) {
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
		if (revoked != RevokedItem{} && claims.StandardClaims.IssuedAt < revoked.IssuedAt && revoked.NewClaims != "") {
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
	
		return
		
	})
}

func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/signin", handleSignIn).Methods(http.MethodPost)
	router.HandleFunc("/api/signup", handleSignUp).Methods(http.MethodPost)
	router.HandleFunc("/api/reset", handlePasswordReset).Methods(http.MethodPost)
	router.HandleFunc("/api/verify", handleEmailVerify).Methods(http.MethodPost)
	router.HandleFunc("/api/refresh", handleTokenRefresh).Methods(http.MethodPost)
	return nil
}