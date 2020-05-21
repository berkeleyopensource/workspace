package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/berkeleyopensource/workspace/auth-service/database"
	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
	"os"
)

var (
	sendgridKey    string
	sendgridClient *sendgrid.Client
	defaultSender  = mail.NewEmail("Workspace Bot", "noreply@projectbot.arifulrigan.com")
	defaultAPI     = "api.arifulrigan.com"
	defaultScheme  = "http"
)

const (
	jwtTokenSize    = 128
	verifyTokenSize = 6
	resetTokenSize  = 6
)

func generateRandomBytes(tokenSize int) ([]byte, error) {
	token := make([]byte, tokenSize)
	_, err := rand.Read(token)
	// Note that err == nil only if we read len(b) bytes.
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
	mux.HandleFunc("api/refresh", handleTokenRefresh)
	// Load sendgrid credentials
	err := godotenv.Load()
	if err != nil {
		return err
	}

	sendgridKey = os.Getenv("SENDGRID_KEY")
	sendgridClient = sendgrid.NewSendClient(sendgridKey)

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

func handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		userRefreshToken(w, r)
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

	// Create access and refresh tokens to be kept as cookies.
	// TODO: come up with a better abstraction for any fields.

	var accessExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)

	var accessToken string
	accessToken, err = NewClaims(map[string]interface{}{
		"Subject": "access", 
		"ExpiresAt": accessExpiresAt.Unix(),
		"Email": credentials.Email,
		"EmailVerified": verified,
	})

	if err != nil {
		http.Error(w, errors.New("Error creating accessToken.").Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "access_token",
		Value: accessToken,
		Expires: accessExpiresAt,
	})

	var refreshExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)

	var refreshToken string
	refreshToken, err = NewClaims(map[string]interface{}{
		"Subject": "refresh", 
		"ExpiresAt": refreshExpiresAt.Unix(),
	})

	if err != nil {
		http.Error(w, errors.New("Error creating refreshToken.").Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token",
		Value: refreshToken,
		Expires: refreshExpiresAt,
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

	// Store (unverified) credentials into the database
	_, err = database.DB.Query("INSERT INTO users(email, hashedPassword, verified, resetToken) VALUES ($1,$2, FALSE, NULL)", credentials.Email, string(hashedPassword))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send verification email
	verifyToken, err := generateRandomBytes(verifyTokenSize)
	base64Token := base64.StdEncoding.EncodeToString(verifyToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = SendEmail(credentials.Email, "Email Verification", "signup-template.html", map[string]interface{}{ "Token": base64Token })
	if err != nil {
		http.Error(w, errors.New("Error sending verification email.").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	var accessExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)

	var accessToken string
	accessToken, err = NewClaims(map[string]interface{}{
		"Subject": "access", 
		"ExpiresAt": accessExpiresAt.Unix(),
		"Email": credentials.Email,
		"EmailVerified": false,
	})

	if err != nil {
		http.Error(w, errors.New("Error creating accessToken.").Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "access_token",
		Value: accessToken,
		Expires: accessExpiresAt,
	})

	var refreshExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)

	var refreshToken string
	refreshToken, err = NewClaims(map[string]interface{}{
		"Subject": "refresh", 
		"ExpiresAt": refreshExpiresAt.Unix(),
	})

	if err != nil {
		http.Error(w, errors.New("Error creating refreshToken.").Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token",
		Value: refreshToken,
		Expires: refreshExpiresAt,
	})

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
		token, err := generateRandomBytes(resetTokenSize)
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
		err = SendEmail(credentials.Email, "Password Reset", "reset-template.html", map[string]interface{}{ "Token": base64Token })
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

		// Update the password field and remove reset token to prevent invalid re-use
		_, err = database.DB.Exec("UPDATE users SET password=$1, resetToken=$2 WHERE resetToken=$3", hashedPassword, "", credentials.Token)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, errors.New("This resetToken is not associated with an account.").Error(), http.StatusNotFound)
			} else {
				http.Error(w, errors.New("Error retrieving information with this resetToken.").Error(), http.StatusInternalServerError)
			}
			return
		}

		// TODO: Invalidate all sessions by issuing new refresh token

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
			log.Print(errors.New("error deleting email corresponding to token"))
			http.Error(w, errors.New("error deleting email corresponding to token").Error(), http.StatusInternalServerError)
		}

	// Verify user account
	} else {
		_, err := database.DB.Exec("UPDATE users SET verified=$1 WHERE token=$2", true, token)
		if err != nil {
			log.Print(errors.New("error finding email corresponding to token"))
			http.Error(w, errors.New("error finding email corresponding to token").Error(), http.StatusInternalServerError)
		}
	}

	//get email of the user
	var email string
	// Check if email exists
	err := database.DB.QueryRow("SELECT email FROM users WHERE token = $1", token).Scan(&email)
	if err == sql.ErrNoRows {
		http.Error(w, errors.New("user email not found, server error").Error(), http.StatusInternalServerError)
		return
	}

	var accessExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)

	var accessToken string
	accessToken, err = NewClaims(map[string]interface{}{
		"Subject": "access", 
		"ExpiresAt": accessExpiresAt.Unix(),
		"Email": email,
		"EmailVerified": true,
	})

	if err != nil {
		http.Error(w, errors.New("Error creating accessToken.").Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "access_token",
		Value: accessToken,
		Expires: accessExpiresAt,
	})

	var refreshExpiresAt = time.Now().Add(DefaultAccessJWTExpiry)

	var refreshToken string
	refreshToken, err = NewClaims(map[string]interface{}{
		"Subject": "refresh", 
		"ExpiresAt": refreshExpiresAt.Unix(),
	})

	if err != nil {
		http.Error(w, errors.New("Error creating refreshToken.").Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token",
		Value: refreshToken,
		Expires: refreshExpiresAt,
	})

	return
}

func userRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := ExtractToken(r, "refresh_token")
	if err != nil {
		if (err == http.ErrNoCookie) {
			http.Error(w, errors.New("Error no cookie.").Error(), http.StatusUnauthorized)
		} else {
			http.Error(w, errors.New("Error getting refreshToken.").Error(), http.StatusBadRequest)
		}
		return
	}

	token, err := VerifyToken(refreshToken)
	if err != nil {
		http.Error(w, errors.New("Error Verifying Token").Error(), http.StatusBadRequest)
	}

	err = ValidateToken(token)
	if err != nil {
		http.Error(w, errors.New("Error Validating Token").Error(), http.StatusBadRequest)
	}

	claims, _ := token.Claims.(jwt.MapClaims)

}
