package main

import (
	"log"
	"net/http"
	"github.com/berkeleyopensource/workspace/auth-service/auth"
	"github.com/gorilla/mux"
)

func main() {
	// Create a new mux router with CORS headers. 
	router := mux.NewRouter()
	router.Use(CORS)

	// Initalize auth routes.
	err := auth.RegisterRoutes(router)
	if err != nil {
		log.Fatal("Error registering auth routes")
	}

	// Start the server
	http.ListenAndServe(":8080", router)
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers:", "*")
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
		} else {
			next.ServeHTTP(w, r)
		}
		return
	})
}
