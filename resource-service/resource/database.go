package resource

import (
	"os"
	"log"
	"fmt"
	"time"
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/joho/godotenv"
)

var db *sql.DB

func init() {

	// initialize environmental variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err.Error())
	}

	// initialize database connection
	var (
		host     = "postgres"
		port     = 5432
		user     = "postgres"
		password = os.Getenv("POSTGRES_PASSWORD")
		dbname   = "auth"
	)

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err = sql.Open("postgres", psqlInfo)
	// Exponential backoff if unsuccessful connection.
	for retries := 0; err != nil && retries < 5; retries++ {
		time.Sleep((50 << retries) * time.Millisecond)
		db, err = sql.Open("postgres", psqlInfo)
	}

	if err != nil {
		log.Fatal("Couldn't connect to postgres.")
	} else {
		log.Print("Connected to postgres.")
	}
}