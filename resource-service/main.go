package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/berkeleyopensource/workspace/resource-service/resource"
	"github.com/joho/godotenv"
	"github.com/gorilla/mux"
)

func main() {
	// Create a new mux router with CORS headers. 
	router := mux.NewRouter()
	router.Use(CORS)

	// Initalize auth routes.
	err = auth.RegisterRoutes(router)
	if err != nil {
		log.Fatal("Error registering auth routes")
	}

	// Start the server
	http.ListenAndServe(":8484", router)
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
	})
}
