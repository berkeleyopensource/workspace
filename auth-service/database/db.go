package database

import (
	"database/sql"
)

var (
	DB *sql.DB
)

func InitializeUsersTable() error {

	//create auth database
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS users (
			email VARCHAR(320),
			hashedPassword VARCHAR(60)
		);`)
	if err != nil {
		panic(err)
	}

	return nil
}
