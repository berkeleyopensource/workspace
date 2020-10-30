package main

import (
	"log"
	"net/http"
	"github.com/berkeleyopensource/workspace/auth-service/auth"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
)

func main() {
	router := mux.NewRouter()

	// Create a new mux router with CORS headers. 
	router.Use(CORS)

	// Forward headers as we're using nginx to reverse proxy.
	router.Use(handlers.ProxyHeaders)

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
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
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
