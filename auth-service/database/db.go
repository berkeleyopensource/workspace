package database

import (
	"database/sql"
	"log"
)

var (
	DB *sql.DB
)

func InitializeUsersTable() error {
	// Create the auth database with table users
	_, err := DB.Exec(`CREATE TABLE users (
		email VARCHAR(320),
		hashedPassword TEXT,
		verified boolean,
		resetToken bytea,
		verifiedToken TEXT,
		userId uuid
	)`)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	log.Print("Database 'auth' successfully created!")
	return nil
}
