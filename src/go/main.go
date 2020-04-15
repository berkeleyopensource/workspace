package main

import (
	"database/sql"
	"github.com/eecscord/workspace/src/go/auth"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"net/http"
)

func main() {
	//create http mux
	mux := http.NewServeMux()

	//database
	db, err := sql.Open("mysql", "root:password@tcp(localhost:3306)/users")
	//db, err := sql.Open("mysql", "admin:admin@/users")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal(err.Error())
	} else {
		log.Println("pinged")
	}

	//register routes
	registerAllRoutes(mux)

	http.ListenAndServe(":8080", mux)

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
