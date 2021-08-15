package app

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/rosered11/golang-jwt-token/domain"
	"github.com/rosered11/golang-jwt-token/service"
)

func Start() {
	router := mux.NewRouter()
	sqlClient := getDbClient()

	// repository
	authRepository := domain.NewAuthRepositoryDb(sqlClient)

	// service
	service := service.NewAuthService(authRepository)

	// wire
	ah := NewAuthHandler(service)

	// define routing
	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodGet)

	address := "localhost"
	port := "8001"
	http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router)
}

func getDbClient() *sqlx.DB {
	client, err := sqlx.Open("mysql", "root:codecamp@tcp(localhost:3306)/banking")
	if err != nil {
		panic(err)
	}
	// See "Important settings" section.
	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)
	return client
}
