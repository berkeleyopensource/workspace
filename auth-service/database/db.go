package database

import (
	"database/sql"
	"fmt"
)

var (
	DB *sql.DB
)

func InitializeUsersTable() error {

	//create auth database
	_, err := DB.Exec(`CREATE TABLE users (
			email VARCHAR(320),
			hashedPassword TEXT,
			verified boolean,
			resetToken TEXT
		)`)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	fmt.Println("query executed")

	return nil
}

func InitializeTokensTable() error {
	_, err := DB.Exec(`CREATE TABLE tokens (
		email VARCHAR(320),
		token TEXT
	)`)
}
