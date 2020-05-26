package auth

import (
	"log"
	"time"
	"net/http"
	"crypto/rand"
	"database/sql"
	"errors"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"github.com/berkeleyopensource/workspace/auth-service/database"
	"github.com/google/uuid"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

const (
	tokenSize = 6;
)

func generateRandomBytes(tokenSize int) ([]byte, error) {
	token := make([]byte, tokenSize)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/signin", handleSignIn).Methods(http.MethodPost)
	router.HandleFunc("/api/signup", handleSignUp).Methods(http.MethodPost)
	router.HandleFunc("/api/reset", handlePasswordReset).Methods(http.MethodPost)
	router.HandleFunc("/api/verify", handleEmailVerify).Methods(http.MethodPost)
	router.HandleFunc("/api/refresh", handleTokenRefresh).Methods(http.MethodPost)
	return nil
}

func handleSignIn(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	var hashedPassword, sessionToken string
	var verified bool

	err = database.DB.QueryRow("select hashedPassword, sessionToken, verified from users where email=$1", credentials.Email).Scan(&hashedPassword, &sessionToken, &verified)
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
		SessionToken: sessionToken,
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
		SessionToken: sessionToken,
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
		http.Error(w, errors.New("Error hashing password").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Create a new random session token
	sessionToken := uuid.New().String();

	// Create a new verification token
	verifyToken, err := generateRandomBytes(tokenSize)
	base64Token := base64.StdEncoding.EncodeToString(verifyToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Store credentials in database
	_, err = database.DB.Query("INSERT INTO users(email, hashedPassword, verified, resetToken, sessionToken, verifiedToken) VALUES ($1, $2, FALSE, NULL, $3, $4)", credentials.Email, string(hashedPassword), sessionToken, base64Token)
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
		SessionToken: sessionToken,
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
		SessionToken: sessionToken,
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
	err = SendEmail(credentials.Email, "Email Verification", "user-signup.html", map[string]interface{}{ "Token": base64Token })
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
		token, err := generateRandomBytes(tokenSize)
		base64Token := base64.StdEncoding.EncodeToString(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Store reset token into database
		_, err = database.DB.Exec("UPDATE users SET resetToken=$1 WHERE email=$2", base64Token, credentials.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		// Create email with password reset link
		err = SendEmail(credentials.Email, "Password Reset", "password-reset.html", map[string]interface{}{ "Token": base64Token })
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

		// Hash the password using bcrypt
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, errors.New("Error hashing password").Error(), http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		var oldSessionToken string	
		err = database.DB.QueryRow("SELECT sessionToken from users where resetToken=$1", credentials.Token).Scan(&oldSessionToken)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("This resetToken is not associated with an account.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, errors.New("Error retrieving information with this resetToken.").Error(), http.StatusInternalServerError)
				log.Print(err.Error())
			}
			return
		}		

		// Add oldSessionToken to list of revoked tokens
		err = setRevokedItem(oldSessionToken, RevokedItem{ invalid: true })
		if err != nil {
			return
		}

		// Create a new random session token
		newSessionToken := uuid.New().String();

		// Update the password field and remove reset token to prevent invalid re-use
		_, err = database.DB.Exec("UPDATE users SET password=$1, resetToken=$2, sessionToken=$3 WHERE resetToken=$4", hashedPassword, "", newSessionToken, credentials.Token)
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

	// Unpack verification token and invalid fields.
	queryParam, ok := r.URL.Query()["token"]
	token := queryParam[0]
	if !ok || len(queryParam[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		return
	}

	queryParam, ok = r.URL.Query()["invalid"]
	invalid := queryParam[0]
	if !ok || len(queryParam[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		return
	}

	// Delete account if invalid field is false
	if invalid == "false" {
		_, err := database.DB.Exec("DELETE FROM users WHERE verifiedToken=$1", token)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("No account is associated with this token.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Print(err.Error())
			}
		}

	// Verify user account
	} else {

		var email, sessionToken string	
		err = database.DB.QueryRow("SELECT email, sessionToken from users where resetToken=$1", credentials.Token).Scan(&email, &sessionToken)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("No account is associated with this token.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Print(err.Error())
			}
			return
		}	

		_, err := database.DB.Exec("UPDATE users SET verified=$1 WHERE verifiedToken=$2", true, token)
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
			SessionToken: sessionToken,
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

		// Update list of stale tokens
		err = setRevokedItem(sessionToken, RevokedItem{ stale: accessToken })
		if err != nil {
			return
		}		

	}

	return
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
	err = getRevokedItem(claims.SessionToken, revoked)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Clear cookies if refreshToken is revoked.
	if (revoked != RevokedItem{} && revoked.invalid == true) {
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

	// Check if accessToken has stale claims.
	oldAccessToken := accessCookie.Value
	if (revoked != RevokedItem{} && revoked.stale != "") {
		oldAccessToken = revoked.stale
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