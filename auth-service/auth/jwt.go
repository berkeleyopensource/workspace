package auth

type Claims struct {
	iss            string `json:"iss"`
	iat            int64  `json:"iat"`
	exp            int64  `json:"exp"`
	email          string `json:"email"`
	email_verified bool   `json:"email_verified"`
}
