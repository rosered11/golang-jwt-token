package app

import (
	"encoding/json"
	"net/http"

	"github.com/rosered11/golang-jwt-token/dto"
	"github.com/rosered11/golang-jwt-token/service"
	"github.com/rosered11/golang101-lib/logger"
)

type AuthHandler struct {
	service service.AuthService
}

func NewAuthHandler(service service.AuthService) AuthHandler {
	return AuthHandler{service: service}
}

func (h AuthHandler) Login(rw http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		logger.Error("Error while decoding login request: " + err.Error())
		rw.WriteHeader(http.StatusBadRequest)
	} else {
		token, err := h.service.Login(loginRequest)

		if err != nil {
			writeResponse(rw, err.Code, err.AsMessage())
		} else {
			writeResponse(rw, http.StatusOK, *token)
		}
	}
}

/*
Sample: /auth/verify?token=aa.b.c&routeName=GetCustomer&customer_id=2000&account=2000
*/
func (h AuthHandler) Verify(rw http.ResponseWriter, r *http.Request) {
	urlParams := map[string]string{}

	// converting from Query to map type
	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		err := h.service.Verify(urlParams)
		if err != nil {
			writeResponse(rw, err.Code, notAuthorizedResponse(err.Message))
		} else {
			writeResponse(rw, http.StatusOK, authorizedResponse())
		}
	} else {
		writeResponse(rw, http.StatusForbidden, notAuthorizedResponse("missing token"))
	}
}

func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      msg,
	}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}

func writeResponse(rw http.ResponseWriter, code int, data interface{}) {
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(code)
	err := json.NewEncoder(rw).Encode(data)
	if err != nil {
		panic(err)
	}
}
