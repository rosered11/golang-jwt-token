package service

import (
	"fmt"

	"github.com/rosered11/golang101-lib/errors"
	"github.com/rosered11/golang101-lib/logger"

	"github.com/golang-jwt/jwt"
	"github.com/rosered11/golang-jwt-token/domain"
	"github.com/rosered11/golang-jwt-token/dto"
)

type AuthService interface {
	Login(dto.LoginRequest) (*string, *errors.AppError)
	Verify(map[string]string) *errors.AppError
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func NewAuthService(repo domain.AuthRepository) DefaultAuthService {
	return DefaultAuthService{repo: repo, rolePermissions: domain.GetRolePermissions()}
}

func (service DefaultAuthService) Login(request dto.LoginRequest) (*string, *errors.AppError) {
	login, err := service.repo.FindBy(request.Username, request.Password)
	if err != nil {
		return nil, err
	}

	token, err := login.GenerateToken()

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (service DefaultAuthService) Verify(urlParams map[string]string) *errors.AppError {
	// convert string token to JWT struct
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return errors.NewAuthorizationError(err.Error())
	} else {
		/*
			Checking the validity of the token, this verifies the expiry
			time and the signature of token
		*/

		if jwtToken.Valid {
			// type cast the token claim to jwt.MapClaims
			claims := jwtToken.Claims.(*domain.Claims)

			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return errors.NewAuthorizationError("request not verify with the token claims")
				}
			}
			// verify of the role is authrized to use route
			isAuthorized := service.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return errors.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return errors.NewAuthorizationError("invalid token")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})

	if err != nil {
		logger.Error("Errors while parse token string to jwt: " + err.Error())
		return nil, err
	}
	return token, nil
}
