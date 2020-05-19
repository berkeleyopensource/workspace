package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/berkeleyopensource/workspace/auth-service/database"
	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
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

func constructVerifyURL(token, invalid string) (string, error) {
	u, err := url.Parse(defaultAPI)
	if err != nil {
		return "", err
	}
	u.Scheme = defaultScheme
	q := u.Query()
	q.Set("token", token)
	q.Set("invalid", invalid)
	u.RawQuery = q.Encode()
	return u.String(), nil

}

func RegisterRoutes(mux *http.ServeMux) error {

	// Initialize routes
	mux.HandleFunc("/api/signin", handleSignIn)
	mux.HandleFunc("/api/signup", handleSignUp)
	mux.HandleFunc("/api/reset", handleResetPassword)
	mux.HandleFunc("/api/verify", handleVerifyEmail)

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
	w.Header().Set("Access-Control-Allow-Origin", "https://localhost:3000")
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
	w.Header().Set("Access-Control-Allow-Origin", "https://localhost:3000")
	switch r.Method {
	case "POST":
		userSignUp(w, r)
		return
	default:
		http.Error(w, errors.New("Only POST requests are allowed on this endpoint.").Error(), http.StatusBadRequest)
		return
	}
}

func handleResetPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://localhost:3000")
	switch r.Method {
	case "POST":
		userResetPassword(w, r)
		return
	default:
		http.Error(w, errors.New("Only POST requests are allowed on this endpoint.").Error(), http.StatusBadRequest)
		return
	}
}

func handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		userVerifyEmail(w, r)
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

	// Check if hashed password matches the one corresponding to the email
	var hashedPassword, verified string
	err = database.DB.QueryRow("select hashedPassword, verified from users where email=$1", credentials.Email).Scan(&hashedPassword, &verified)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, errors.New("This email is not associated with an account.").Error(), http.StatusNotFound)
		} else {
			http.Error(w, errors.New("Error retrieving information with this email.").Error(), http.StatusInternalServerError)
		}
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
		http.Error(w, errors.New("The password you've entered is incorrect.").Error(), http.StatusUnauthorized)
		return
	}

	var tokenString string
	var refreshString string
	expirationTime := time.Now().Add(defaultAccessJWTExpiry)

	if verified == true {
		tokenString, err = NewClaim(email, "access", true)
		refreshString, err = NewClaim(email, "refresh", true)
	} else {
		tokenString, err = NewClaim(email, "access", false)
		refreshString, err = NewClaim(email, "refresh", false)
	}

	if err != nil {
		http.Error(w, errors.New("Error creating verification token").Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   tokenString,
		Expires: DefaultAccessJWTExpiry,
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshString,
		Expires: DefaultRefreshJWTExpiry,
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
	// implement following line after database has been edited
	//_, err = database.DB.Query("INSERT INTO users(email, hashedPassword, verified) VALUES (@email,@hashedPassword, @verified)", sql.Named("email", credentials.Email), sql.Named("hashedPassword", string(hashedPassword)), sql.Named("verified", 0))
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
	validURL, err := constructVerifyURL(base64Token, "true")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	invalidURL, err := constructVerifyURL(base64Token, "false")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	subject := "User Registration"
	body := fmt.Sprintf("User registration, but verification required: \n Verify String: %s \n Not you?: %s", validURL, invalidURL)
	err = SendEmail(credentials.Email, subject, body)
	if err != nil {
		http.Error(w, errors.New("Error sending verification email").Error(), http.StatusInternalServerError)
		log.Fatal(err.Error())
		return
	}

	tokenString, err := NewClaims(email, "access", false)
	if err != nil {
		http.Error(w, errors.New("Error creating access token").Error(), http.StatusInternalServerError)
	}

	refreshString, err = NewClaims(email, "refresh", false)
	if err != nil {
		http.Error(w, errors.New("Error creating refresh token").Error(), http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   tokenString,
		Expires: DefaultAccessJWTExpiry,
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshString,
		Expires: DefaultRefreshJWTExpiry,
	})

	return
}

func userResetPassword(w http.ResponseWriter, r *http.Request) {

	//Obtain user credentials
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		log.Fatal(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if hashed password matches the one corresponding to the email
	var hashedPassword string
	err = database.DB.QueryRow("select hashedPassword from users where email=$1", credentials.Email).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	//update previous token previously existing token
	token, err := generateRandomBytes(resetTokenSize)
	base64Token := base64.StdEncoding.EncodeToString(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = database.DB.Exec("UPDATE users SET resetToken=$1 WHERE email=$2", base64Token, credentials.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	// Send token to user
	fmt.Println("token: ", token)
	fmt.Println("base64 token: ", base64Token)
	subject := fmt.Sprintf("Reset token for user: %s", credentials.Email)
	body := fmt.Sprintf("Reset Token: %s", base64Token)
	err = SendEmail(credentials.Email, subject, body)
	if err != nil {
		http.Error(w, errors.New("Error sending verification email").Error(), http.StatusInternalServerError)
		log.Fatal(err.Error())
		return
	}

	return
}

func userVerifyEmail(w http.ResponseWriter, r *http.Request) {

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
	err := database.DB.QueryRow("SELECT email FROM users WHERE token = $1", token).scan(&email)
	if err == sql.ErrNoRows {
		http.Error(w, errors.New("user email not found, server error").Error(), http.StatusInternalServerError)
		return
	}

	tokenString, err := NewClaim(email, "access", true)
	if err != nil {
		http.Error(w, errors.New("Error creating verification token").Error(), http.StatusInternalServerError)
	}

	refreshString, err = NewClaims(email, "refresh", true)
	if err != nil {
		http.Error(w, errors.New("Error creating refresh token").Error(), http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   tokenString,
		Expires: DefaultAccessJWTExpiry,
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshString,
		Expires: DefaultRefreshJWTExpiry,
	})

	return
}
