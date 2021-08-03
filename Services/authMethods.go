package services

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"time"
)

var jwtKey = []byte("secret_key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//go get github.com/dgrijalva/jwt-go -------- to get jwt library
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(httpResponse http.ResponseWriter, httpRequest *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(httpRequest.Body).Decode(&credentials)
	if err != nil {
		httpResponse.WriteHeader(http.StatusBadRequest)
		return
	}
	expectedPassword, ok := users[credentials.Username]
	if !ok || expectedPassword != credentials.Password {
		httpResponse.WriteHeader(http.StatusUnauthorized)
	}

	expirationTime := time.Now().Add(time.Minute * 5)
	claims := &Claims{Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		httpResponse.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(httpResponse, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func Home(httpResponse http.ResponseWriter, httpRequest *http.Request) {
	cookie, err := httpRequest.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			httpResponse.WriteHeader(http.StatusUnauthorized)
			return
		}
		httpResponse.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenString := cookie.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			httpResponse.WriteHeader(http.StatusUnauthorized)
			return
		}
		httpResponse.WriteHeader(http.StatusBadRequest)
		return
	}

	if !token.Valid {
		httpResponse.WriteHeader(http.StatusUnauthorized)
		return
	}

	httpResponse.Write([]byte(fmt.Sprintf(
		"Hello, %s",
		claims.Username,
	)))
}

func Refresh(httpResponse http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			httpResponse.WriteHeader(http.StatusUnauthorized)
			return
		}
		httpResponse.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenString := cookie.Value

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			httpResponse.WriteHeader(http.StatusUnauthorized)
			return
		}
		httpResponse.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		httpResponse.WriteHeader(http.StatusUnauthorized)
		return
	}

	// if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }

	expirationTime := time.Now().Add(time.Minute * 5)

	claims.ExpiresAt = expirationTime.Unix()

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newTokenString, err := newToken.SignedString(jwtKey)

	if err != nil {
		httpResponse.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(httpResponse,
		&http.Cookie{
			Name:    "refresh_token",
			Value:   newTokenString,
			Expires: expirationTime,
		})

}
