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
	"github.com/berkeleyopensource/workspace/auth-service/database"
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

func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/signin", handleSignIn).Methods(http.MethodPost)
	router.HandleFunc("/api/signup", handleSignUp).Methods(http.MethodPost)
	router.HandleFunc("/api/reset", handlePasswordReset).Methods(http.MethodPost)
	router.HandleFunc("/api/verify", handleEmailVerify).Methods(http.MethodPost)
	router.HandleFunc("/api/refresh", handleTokenRefresh).Methods(http.MethodPost)
	return nil
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
	Invalid  bool   `json:"invalid"`
}

func handleSignIn(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	var hashedPassword, userId string
	var verified bool

	err = database.DB.QueryRow("select hashedPassword, userId, verified from users where email=$1", credentials.Email).Scan(&hashedPassword, &userId, &verified)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, errors.New("This email is not associated with an account.").Error(), http.StatusNotFound)
		} else {
			http.Error(w, errors.New("Error retrieving information with this email.").Error(), http.StatusInternalServerError)
			log.Print(err.Error())
		}
		return
	}

	// Check if hashed password matches the one corresponding to the email
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); 
	if err != nil {
		http.Error(w, errors.New("The password you've entered is incorrect.").Error(), http.StatusUnauthorized)
		return
	}

	// Set access token as a cookie.
	var accessExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		Email: credentials.Email,
		EmailVerified: verified,
		UserId: userId,
		StandardClaims: jwt.StandardClaims{
			Subject: "access", 
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer: defaultJWTIssuer,
			IssuedAt: time.Now().Unix(),
		},
	})
	if err != nil {
		http.Error(w, errors.New("Error creating accessToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "access_token",
		Value: accessToken,
		Expires: accessExpiresAt,
	})

	// Set refresh token as a cookie.
	var refreshExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UsedId: userIdv,
		StandardClaims: jwt.StandardClaims{
			Subject: "refresh", 
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer: defaultJWTIssuer,
			IssuedAt: time.Now().Unix(),
		},
	})

	if err != nil {
		http.Error(w, errors.New("Error creating refreshToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token",
		Value: refreshToken,
		Expires: refreshExpiresAt,
	})

	return
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Check if email exists
	rows := database.DB.QueryRow("SELECT email FROM users WHERE email = $1", credentials.Email)
	var email string
	if err = rows.Scan(&email); err != sql.ErrNoRows {
		http.Error(w, errors.New("This email is already associated with an account.").Error(), http.StatusConflict)
		return
	}

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, errors.New("Error hashing password.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Create a new random session token
	userId := uuid.New().String();

	// Create a new verification token
	verifyToken := getRandomBase62(tokenSize)

	// Store credentials in database
	_, err = database.DB.Query("INSERT INTO users(email, hashedPassword, verified, resetToken, userId, verifiedToken) VALUES ($1, $2, FALSE, NULL, $3, $4)", credentials.Email, string(hashedPassword), userId, verifyToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Set access token as a cookie.
	var accessExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		Email: credentials.Email,
		EmailVerified: false,
		UsedId: userId,
		StandardClaims: jwt.StandardClaims{
			Subject: "access", 
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer: defaultJWTIssuer,
			IssuedAt: time.Now().Unix(),
		},
	})
	if err != nil {
		http.Error(w, errors.New("Error creating accessToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "access_token",
		Value: accessToken,
		Expires: accessExpiresAt,
	})

	// Set refresh token as a cookie.
	var refreshExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UsedId: userId,
		StandardClaims: jwt.StandardClaims{
			Subject: "refresh", 
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer: defaultJWTIssuer,
			IssuedAt: time.Now().Unix(),
		},
	})

	if err != nil {
		http.Error(w, errors.New("Error creating refreshToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token",
		Value: refreshToken,
		Expires: refreshExpiresAt,
	})

	// Send verification email
	err = SendEmail(credentials.Email, "Email Verification", "user-signup.html", map[string]interface{}{ "Token": verifyToken })
	if err != nil {
		http.Error(w, errors.New("Error sending verification email.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	
	return
}

func handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// 1st pass: email, no token
	if (credentials.Email != "" && credentials.Password == "") {

		// Create a password reset token
		resetToken := getRandomBase62(tokenSize)

		// Hash the reset token using SHA-256
		hashedResetToken := sha256.Sum256([]byte(resetToken))
		stringHashed := string(hashedResetToken[:])

		// Store the hashed reset token in database
		_, err = database.DB.Exec("UPDATE users SET resetToken=$1 WHERE email=$2", stringHashed, credentials.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		// Create email with password reset link
		err = SendEmail(credentials.Email, "Password Reset", "password-reset.html", map[string]interface{}{ "Token": resetToken })
		if err != nil {
			http.Error(w, errors.New("Error sending password reset email.").Error(), http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Return with 202 response
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// 2nd pass: token, no email
	if (credentials.Email == "" && credentials.Password != "") {

		// Hash the reset token using SHA-256
		hashedResetToken := sha256.Sum256([]byte(credentials.Token))
		stringHashed := string(hashedResetToken[:])

		//  Get the userId associated with the reset token.
		var userId string	
		err = database.DB.QueryRow("SELECT userId from users where resetToken=$1", stringHashed).Scan(&userId)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("This resetToken is not associated with an account.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, errors.New("Error retrieving information with this resetToken.").Error(), http.StatusInternalServerError)
				log.Print(err.Error())
			}
			return
		}		

		// Add userId to list of revoked tokens.
		err = setRevokedItem(userId, RevokedItem{ Invalid: true, IssuedAt: time.Now().Unix() })
		if err != nil {
			http.Error(w, errors.New("Error retrieving information with this resetToken.").Error(), http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Hash the password using bcrypt
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, errors.New("Error hashing password.").Error(), http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Update the password field and remove reset token to prevent invalid re-use
		_, err = database.DB.Exec("UPDATE users SET hashedPassword=$1, resetToken=$2 WHERE resetToken=$3", hashedPassword, nil, stringHashed)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("This resetToken is not associated with an account.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, errors.New("Error retrieving information with this resetToken.").Error(), http.StatusInternalServerError)
				log.Print(err.Error())
			}
			return
		}

		// Return with 204 response		
		w.WriteHeader(http.StatusNoContent)
		return
	}

	http.Error(w, errors.New("Error with email or password fields.").Error(), http.StatusBadRequest)
	return
}

func handleEmailVerify(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Delete account if invalid field is true
	if credentials.Invalid {

		_, err := database.DB.Exec("DELETE FROM users WHERE verifiedToken=$1", credentials.Token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Print(err.Error())
		}

	// Verify user account
	} else {

		var email, userId string	
		err = database.DB.QueryRow("SELECT email, userId from users where verifiedToken=$1", credentials.Token).Scan(&email, &userId)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("No account is associated with this token.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Print(err.Error())
			}
			return
		}	

		_, err := database.DB.Exec("UPDATE users SET verified=$1, verifiedToken=$2 WHERE verifiedToken=$3", true, "", credentials.Token)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("No account is associated with this token.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Print(err.Error())
			}
		}

		// Set access token as a cookie.
		var accessExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
		var accessToken string
		accessToken, err = setClaims(AuthClaims{
			Email: email,
			EmailVerified: true,
			userId: userId,
			StandardClaims: jwt.StandardClaims{
				Subject: "access", 
				ExpiresAt: accessExpiresAt.Unix(),
				Issuer: defaultJWTIssuer,
				IssuedAt: time.Now().Unix(),
			},
		})
		if err != nil {
			log.Print(err.Error())
			return
		}

		// Update list of stale tokens
		err = setRevokedItem(userId, RevokedItem{ NewClaims: accessToken, IssuedAt: time.Now().Unix() })
		if err != nil {
			log.Print(err.Error())
			return
		}
	}
}

func handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
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
}