package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/eecscord/workspace/auth-service/auth"
	"github.com/eecscord/workspace/auth-service/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	//load env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("couldn't load env file")
	}

	//create http mux
	mux := http.NewServeMux()

	//database)
	err = initializeDB()
	if err != nil {
		panic(err)
	}
	defer database.DB.Close()

	//register routes
	registerAllRoutes(mux)

	//start the server
	http.ListenAndServe(":80", mux)

}

func initializeDB() error {
	//database credentials
	var (
		host     = "172.28.1.1"
		port     = 5432
		user     = "postgres"
		password = os.Getenv("DB_PASSWORD")
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

func registerAllRoutes(mux *http.ServeMux) {
	err := auth.RegisterRoutes(mux)
	logError(err)
}

func logError(err error) {
	if err != nil {
		log.Fatal("Error registering auth routes")
	}
}
