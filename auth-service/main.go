package main

import (
	"database/sql"
	"fmt"
	"github.com/eecscord/workspace/auth-service/auth"
	"github.com/eecscord/workspace/auth-service/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"os"
)

func main() {
	//load env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("couldn't load env file")
	}

	//database credentials
	var (
		host     = "172.28.1.2"
		port     = 5432
		user     = "postgres"
		password = os.Getenv("DB_PASSWORD")
		dbname   = "auth"
	)

	//create http mux
	mux := http.NewServeMux()

	//database)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	database.DB, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer database.DB.Close()

	err = database.InitializeUsersTable()
	if err != nil {
		panic(err)
	}
	fmt.Println("connected and created tables")

	//register routes
	registerAllRoutes(mux)

	//start the server
	http.ListenAndServe(":80", mux)

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
