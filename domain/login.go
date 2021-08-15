package domain

import (
	"database/sql"
	"strings"
	"time"

	"github.com/rosered11/golang101-lib/errors"
	"github.com/rosered11/golang101-lib/logger"

	"github.com/golang-jwt/jwt"
)

const TOKEN_DURATION = time.Hour

type Login struct {
	Username   string         `db:"username"`
	CustomerId sql.NullString `db:"customer_id"`
	Accounts   sql.NullString `db:"account_numbers"`
	Role       string         `db:"role"`
}

func (l Login) GenerateToken() (*string, *errors.AppError) {
	var claim jwt.MapClaims

	if l.Accounts.Valid && l.CustomerId.Valid {
		claim = l.claimForUser()
	} else {
		claim = l.claimForUser()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	signTokenAsString, err := token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed while signing token: " + err.Error())
		return nil, errors.NewUnexpectedError("cann't generate token")
	}
	return &signTokenAsString, nil
}

func (l Login) claimForUser() jwt.MapClaims {
	accounts := strings.Split(l.Accounts.String, ",")
	return jwt.MapClaims{
		"customer_id": l.CustomerId.String,
		"role":        l.Role,
		"username":    l.Username,
		"accounts":    accounts,
		"exp":         time.Now().Add(TOKEN_DURATION).Unix(),
	}
}

func (l Login) claimForAdmin() jwt.MapClaims {
	return jwt.MapClaims{
		"role":     l.Role,
		"username": l.Username,
		"exp":      time.Now().Add(TOKEN_DURATION).Unix(),
	}
}
