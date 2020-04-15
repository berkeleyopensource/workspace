package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		//TODO: login
		io.WriteString(w, "login here")
	case "POST":
		registerUser(w, r)
		return
	default:
		http.Error(w, errors.New("bad request").Error(), http.StatusBadRequest)
		return
	}
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	newUser := User{}
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	credentials := fmt.Sprintf("user:%s and password:%s", newUser.Username, newUser.Password)
	io.WriteString(w, credentials)
}

func RegisterRoutes(mux *http.ServeMux) error {

	mux.HandleFunc("/auth/user", userHandler)

	return nil
}
