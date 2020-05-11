package auth

type Credentials struct {
	Email    string
	Password string
}

type Reset struct {
	Email string
}
