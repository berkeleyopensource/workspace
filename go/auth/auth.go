package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/eecscord/workspace/go/database"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
)

func userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		loginUser(w, r)
	case "POST":
		registerUser(w, r)
		return
	default:
		http.Error(w, errors.New("bad request").Error(), http.StatusBadRequest)
		return
	}
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	credentials := User{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//compare password
	var hashedPassword string
	err = database.DB.QueryRow("select hashedPassword from users where username=?", credentials.Username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	io.WriteString(w, "logged in!")
}

func registerUser(w http.ResponseWriter, r *http.Request) {

	//get info from json
	newUser := User{}
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//check if user exists
	rows, err := database.DB.Query("select username from users where username=?", newUser.Username)
	if rows.Next() {
		http.Error(w, errors.New("Username already taken").Error(), http.StatusBadRequest)
		return
	}

	//hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, errors.New("error hashing password").Error(), http.StatusInternalServerError)
		return
	}

	//put credentials into the database
	_, err = database.DB.Query("INSERT INTO users(username, hashedPassword) VALUES (?,?)", newUser.Username, string(hashedPassword))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func RegisterRoutes(mux *http.ServeMux) error {

	mux.HandleFunc("/auth/user", userHandler)

	return nil
}
