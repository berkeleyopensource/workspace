package auth

import (
	"log"
	"time"
	"net/http"
	"math/rand"
	"errors"
	"strings"
	"encoding/json"
	"crypto/sha256"
	"database/sql"
	"golang.org/x/crypto/bcrypt"
	"github.com/google/uuid"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
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
	router.HandleFunc("/api/logout", handleLogout).Methods(http.MethodPost)
	router.HandleFunc("/api/verify", handleVerify).Methods(http.MethodPost)
	router.HandleFunc("/api/reset", handleReset).Methods(http.MethodPost)
	router.HandleFunc("/api/refresh", handleRefresh).Methods(http.MethodPost)
	router.HandleFunc("/api/webhook", handleWebhook).Methods(http.MethodGet)
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

	err = db.QueryRow("select hashedPassword, userId, verified from users where email=$1", credentials.Email).Scan(&hashedPassword, &userId, &verified)
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
		Hasura: map[string]interface{} {
			"x-hasura-role": "user",
			"x-hasura-allowed-roles": "user",
			"x-hasura-user-id": userId,
		},
		StandardClaims: jwt.StandardClaims{
			Subject: "access", 
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer: defaultJWTIssuer,
			IssuedAt: time.Now().Unix(),
		},
	})
	if err != nil {
		http.Error(w, errors.New("ServerError: Error creating accessToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "accessToken",
		Value: accessToken,
		Path: "/",
		Expires: accessExpiresAt,
		Secure: true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	// Set refresh token as a cookie.
	var refreshExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserId: userId,
		StandardClaims: jwt.StandardClaims{
			Subject: "refresh", 
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer: defaultJWTIssuer,
			IssuedAt: time.Now().Unix(),
		},
	})

	if err != nil {
		http.Error(w, errors.New("ServerError: Error creating refreshToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "refreshToken",
		Value: refreshToken,
		Path: "/api/refresh",
		Expires: refreshExpiresAt,
		Secure: true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string] string{"userId": userId, "accessToken": accessToken})
	if err != nil {
		http.Error(w, errors.New("Error: interal server error creating json payload.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())	
	}

	return
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, errors.New("Error decoding json credentials.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Check if email exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS (SELECT email FROM users WHERE email = $1)", credentials.Email).Scan(&exists)
	if err != nil {
		http.Error(w, errors.New("Error checking if email exists.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())		
		return
	}
	if exists == true {
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

	// Create a new random userId
	userId := uuid.New().String();

	// Create a new verification token
	verifyToken := getRandomBase62(8)

	// Store credentials in database
	_, err = db.Query("INSERT INTO users(email, hashedPassword, verified, resetToken, userId, verifiedToken) VALUES ($1, $2, FALSE, NULL, $3, $4)", credentials.Email, string(hashedPassword), userId, verifyToken)
	if err != nil {
		http.Error(w, errors.New("Error storing credentials into database.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Set access token as a cookie.
	var accessExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		Email: credentials.Email,
		EmailVerified: false,
		UserId: userId,
		Hasura: map[string]interface{} {
			"x-hasura-role": "user",
			"x-hasura-allowed-roles": "user",
			"x-hasura-user-id": userId,
		},
		StandardClaims: jwt.StandardClaims{
			Subject: "access", 
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer: defaultJWTIssuer,
			IssuedAt: time.Now().Unix(),
		},
	})
	if err != nil {
		http.Error(w, errors.New("ServerError: Error creating accessToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "accessToken",
		Value: accessToken,
		Path: "/",
		Expires: accessExpiresAt,
		Secure: true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	// Set refresh token as a cookie.
	var refreshExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserId: userId,
		StandardClaims: jwt.StandardClaims{
			Subject: "refresh", 
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer: defaultJWTIssuer,
			IssuedAt: time.Now().Unix(),
		},
	})

	if err != nil {
		http.Error(w, errors.New("ServerError: Error creating refreshToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "refreshToken",
		Value: refreshToken,
		Path: "/api/refresh",
		Expires: refreshExpiresAt,
		Secure: true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	// Send verification email
	err = SendEmail(credentials.Email, "Email Verification", "user-signup.html", map[string]interface{}{ "Token": verifyToken })
	if err != nil {
		http.Error(w, errors.New("Error sending verification email.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string] string{"userId": userId, "accessToken": accessToken})
	if err != nil {
		http.Error(w, errors.New("Error: interal server error creating json payload.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())	
	}

	return
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	var expiresAt = time.Now().Add(-1 * time.Minute)
	http.SetCookie(w, &http.Cookie{ Name: "accessToken",  Value: "", Path: "/",            Expires: expiresAt, Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode})
	http.SetCookie(w, &http.Cookie{ Name: "refreshToken", Value: "", Path: "/api/refresh", Expires: expiresAt, Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode})
	return
}

func handleReset(w http.ResponseWriter, r *http.Request) {
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
		resetToken := getRandomBase62(8)

		// Hash the reset token using SHA-256
		hashedResetToken := sha256.Sum256([]byte(resetToken))
		stringHashed := string(hashedResetToken[:])

		// Store the hashed reset token in database
		_, err = db.Exec("UPDATE users SET resetToken=$1 WHERE email=$2", stringHashed, credentials.Email)
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
		err = db.QueryRow("SELECT userId from users where resetToken=$1", stringHashed).Scan(&userId)
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
		err = setRevokedItem(userId, RevokedItem{ Invalid: true, InvalidIssuedAt: time.Now().Unix() })
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
		_, err = db.Exec("UPDATE users SET hashedPassword=$1, resetToken=$2 WHERE resetToken=$3", hashedPassword, nil, stringHashed)
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

func handleVerify(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Delete account if invalid field is true
	if credentials.Invalid {

		_, err := db.Exec("DELETE FROM users WHERE verifiedToken=$1", credentials.Token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Print(err.Error())
		}

	// Verify user account
	} else {

		var email, userId string	
		err = db.QueryRow("SELECT email, userId from users where verifiedToken=$1", credentials.Token).Scan(&email, &userId)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("No account is associated with this token.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Print(err.Error())
			}
			return
		}	

		_, err := db.Exec("UPDATE users SET verified=$1, verifiedToken=$2 WHERE verifiedToken=$3", true, "", credentials.Token)
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
			UserId: userId,
			Hasura: map[string]interface{} {
				"x-hasura-role": "user",
				"x-hasura-allowed-roles": "user",
				"x-hasura-user-id": userId,
			},
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
		err = setRevokedItem(userId, RevokedItem{ NewClaims: accessToken, NewClaimsIssuedAt: time.Now().Unix() })
		if err != nil {
			log.Print(err.Error())
			return
		}
	}
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refreshToken")
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
	err = getRevokedItem(claims.UserId, &revoked)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Clear cookies if refreshToken has been revoked.
	if (revoked != RevokedItem{} && revoked.Invalid == true && claims.StandardClaims.IssuedAt < revoked.InvalidIssuedAt) {
		handleLogout(w, r)
		http.Error(w, errors.New("The refreshToken has been revoked.").Error(), http.StatusUnauthorized)
		return		
	}

	accessCookie, err := r.Cookie("accessToken")
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
		http.Error(w, errors.New("ServerError: Error creating accessToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "accessToken",
		Value: accessToken,
		Path: "/",
		Expires: accessExpiresAt,
		Secure: true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string] string{"userId": claims.UserId, "accessToken": accessToken})
	if err != nil {
		http.Error(w, errors.New("Error: interal server error creating json payload.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
	}

	return
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	var accessToken string

	// Check authorization header for accessToken, else giving public role.
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, errors.New("Error: invalid bearer authorization header.").Error(), http.StatusUnauthorized)
			return
		}
		accessToken = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		log.Print("This request has authorization header: private role given.", r.Header)
	} else {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string] interface{}{
			"x-hasura-role": "public",
		})
		if err != nil {
			http.Error(w, errors.New("Error: interal server error creating json payload.").Error(), http.StatusInternalServerError)
			log.Print(err.Error())
		}
		log.Print("This request has no authorization header: public role given.", r.Header)
		return
	}

	claims, err := getClaims(accessToken)
	if err != nil {
		http.Error(w, errors.New("Error: interal server error from decoding accessToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Check if accessToken has stale claims and needs to be refreshed.
	var revoked RevokedItem
	err = getRevokedItem(claims.UserId, &revoked)
	if err != nil {
		http.Error(w, errors.New("Error: interal server error from validating accessToken.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	if (revoked != RevokedItem{} && revoked.NewClaims != "" && claims.StandardClaims.IssuedAt < revoked.NewClaimsIssuedAt) {
		http.Error(w, errors.New("Error: accessToken is stale and requires refresh.").Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(claims.Hasura)
	if err != nil {
		http.Error(w, errors.New("Error: interal server error creating json payload.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
	}

	return
}