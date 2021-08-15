package domain

import "github.com/rosered11/golang101-lib/errors"

type AuthRepository interface {
	FindBy(string, string) (*Login, *errors.AppError)
}
