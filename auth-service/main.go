package main

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/eecscord/workspace/auth-service/auth"
	"github.com/eecscord/workspace/auth-service/database"
	"github.com/joho/godotenv"
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
	var server = os.Getenv("SERVER")
	var port = 1433
	var user = os.Getenv("USER")
	var password = os.Getenv("PASSWORD")
	var cloudDatabase = os.Getenv("CLOUD_DATABASE")

	//create http mux
	mux := http.NewServeMux()

	//database)
	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;database=%s;",
		server, user, password, port, cloudDatabase)
	fmt.Println(connString)
	// Create connection pool
	database.DB, err = sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal("Error creating connection pool: ", err.Error())
	}

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
