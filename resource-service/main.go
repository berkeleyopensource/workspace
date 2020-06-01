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
	"github.com/berkeleyopensource/workspace/resource-service/database"
	"github.com/joho/godotenv"
	"github.com/gorilla/mux"
)

func main() {
	//load env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("couldn't load env file")
	}

	// Initialize postgres database.
	err = initDB()
	if err != nil {
		log.Fatal("Error initializing database")
	}

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

func initDB() error {
	// database credentials
	var (
		host     = "postgres"
		port     = 5432
		user     = "postgres"
		password = os.Getenv("POSTGRES_PASSWORD")
		dbname   = "auth"
		err      error
		tries    = 0
	)

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	database.DB, err = sql.Open("postgres", psqlInfo)

	for ; err != nil && tries < 5; tries++ {
		time.Sleep(5 * time.Second)
		fmt.Println("retrying")
		database.DB, err = sql.Open("postgres", psqlInfo)
	}
	if err != nil {
		return errors.New("couldnt connect to db")
	}

	err = database.InitializeUsersTable()
	if err != nil {
		return errors.New("error initializing errors table")
	}
	fmt.Println("connected and created tables")

	return nil
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
