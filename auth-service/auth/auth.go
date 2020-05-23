package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/berkeleyopensource/workspace/auth-service/database"
	"golang.org/x/crypto/bcrypt"
	"github.com/google/uuid"
	"log"
	"net/http"
	"time"
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

func RegisterRoutes(mux *http.ServeMux) error {

	// Initialize routes
	mux.HandleFunc("/api/signin", handleSignIn)
	mux.HandleFunc("/api/signup", handleSignUp)
	mux.HandleFunc("/api/reset", handlePasswordReset)
	mux.HandleFunc("/api/verify", handleEmailVerify)

	return nil
}

func handleSignIn(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		userSignIn(w, r)
		return
	default:
		http.Error(w, errors.New("Only POST requests are allowed on this endpoint.").Error(), http.StatusBadRequest)
		return
	}
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		userSignUp(w, r)
		return
	default:
		http.Error(w, errors.New("Only POST requests are allowed on this endpoint.").Error(), http.StatusBadRequest)
		return
	}
}

func handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		userPasswordReset(w, r)
		return
	default:
		http.Error(w, errors.New("Only POST requests are allowed on this endpoint.").Error(), http.StatusBadRequest)
		return
	}
}

func handleEmailVerify(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		userEmailVerify(w, r)
		return
	default:
		http.Error(w, errors.New("Only POST requests are allowed on this endpoint.").Error(), http.StatusBadRequest)
		return
	}
}

func userSignIn(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var hashedPassword string
	var verified bool

	err = database.DB.QueryRow("select hashedPassword, verified from users where email=$1", credentials.Email).Scan(&hashedPassword, &verified)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, errors.New("This email is not associated with an account.").Error(), http.StatusNotFound)
		} else {
			http.Error(w, errors.New("Error retrieving information with this email.").Error(), http.StatusInternalServerError)
		}
		return
	}

	// Check if hashed password matches the one corresponding to the email
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); 
	if err != nil {
		http.Error(w, errors.New("The password you've entered is incorrect.").Error(), http.StatusUnauthorized)
		return
	}

	// Create a new random session token
	sessionToken := uuid.New().String();

	// TODO: Push session token to redis cache on resource server

	// Set the client cookie
	http.SetCookie(w, &http.Cookie{
		Name: "sessionToken",
		Value: sessionToken,
		Expires: time.Now().Add(30 * 24 * time.Hour),
	})

	return
}

func userSignUp(w http.ResponseWriter, r *http.Request) {
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		log.Print(err.Error())
		http.Error(w, errors.New("Error hashing password").Error(), http.StatusInternalServerError)
		return
	}

	// Create a new random session token
	sessionToken := uuid.New().String();

	// Store (unverified) credentials into the database
	_, err = database.DB.Query("INSERT INTO users(email, hashedPassword, verified, resetToken, sessionToken) VALUES ($1, $2, FALSE, NULL, $3)", credentials.Email, string(hashedPassword), sessionToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the client cookie
	http.SetCookie(w, &http.Cookie{
		Name: "sessionToken",
		Value: sessionToken,
		Expires: time.Now().Add(30 * 24 * time.Hour),
	})

	// Send verification email
	verifyToken, err := generateRandomBytes(tokenSize)
	base64Token := base64.StdEncoding.EncodeToString(verifyToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = SendEmail(credentials.Email, "Email Verification", "templates/user-signup.html", map[string]interface{}{ "Token": base64Token })
	if err != nil {
		http.Error(w, errors.New("Error sending verification email.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}
	
	return
}

func userPasswordReset(w http.ResponseWriter, r *http.Request) {

	// Decode json credentials
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, errors.New("Error decoding json body.").Error(), http.StatusInternalServerError)
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
			return
		}

		// Store reset token into database
		_, err = database.DB.Exec("UPDATE users SET resetToken=$1 WHERE email=$2", base64Token, credentials.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		// Create email with password reset link
		err = SendEmail(credentials.Email, "Password Reset", "templates/password-reset.html", map[string]interface{}{ "Token": base64Token })
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
			log.Print(err.Error())
			http.Error(w, errors.New("Error hashing password").Error(), http.StatusInternalServerError)
			return
		}

		var oldSessionToken string	
		err = database.DB.QueryRow("SELECT sessionToken from users where resetToken=$1", credentials.Token).Scan(&oldSessionToken)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("This resetToken is not associated with an account.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, errors.New("Error retrieving information with this resetToken.").Error(), http.StatusInternalServerError)
			}
			return
		}		

		// Create a new random session token
		newSessionToken := uuid.New().String();

		// redis cache del oldSessionToken
		// redis cache set newSessionToken


		// Update the password field and remove reset token to prevent invalid re-use
		_, err = database.DB.Exec("UPDATE users SET password=$1, resetToken=$2, sessionToken=$3 WHERE resetToken=$4", hashedPassword, "", newSessionToken, credentials.Token)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("This resetToken is not associated with an account.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, errors.New("Error retrieving information with this resetToken.").Error(), http.StatusInternalServerError)
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

func userEmailVerify(w http.ResponseWriter, r *http.Request) {

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

	// Delete user account if invalid field is false
	if invalid == "false" {
		_, err := database.DB.Exec("DELETE FROM users WHERE token=$1", token)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("No account is associated with this token.").Error(), http.StatusInternalServerError)
				log.Print(errors.New("No account is associated with this token."))
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}

	// Verify user account
	} else {
		_, err := database.DB.Exec("UPDATE users SET verified=$1 WHERE token=$2", true, token)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("No account is associated with this token.").Error(), http.StatusInternalServerError)
				log.Print(errors.New("No account is associated with this token."))
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}

	return
}
