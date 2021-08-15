package domain

import (
	"database/sql"

	"github.com/rosered11/golang101-lib/errors"
	"github.com/rosered11/golang101-lib/logger"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func NewAuthRepositoryDb(client *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{client: client}
}

func (repo AuthRepositoryDb) FindBy(username string, password string) (*Login, *errors.AppError) {
	var login Login

	sqlVerify := `select username , u.customer_id ,role, GROUP_CONCAT(a.account_id) as account_numbers from users u
	left join accounts a on a.customer_id = u.customer_id
	where username = ? and password = ?
	group by u.username`

	err := repo.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewAuthenticationError("invalid credential")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errors.NewUnexpectedError("unexpected database error")
		}
	}

	return &login, nil
}
