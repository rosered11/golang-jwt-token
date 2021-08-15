package domain

import (
	"github.com/golang-jwt/jwt"
)

const HMAC_SAMPLE_SECRET = "hmacsamplesecret"

type Claims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	//Expiry     int64    `json:"exp"`
	Role string `json:"role"`
	jwt.StandardClaims
}

func (c Claims) IsUserRole() bool {
	return c.Role == "user"
}

func (c Claims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	if c.CustomerId != urlParams["customer_id"] {
		return false
	}

	//if
	return true
}
