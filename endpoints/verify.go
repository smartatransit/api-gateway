package endpoints

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type Authorization struct {
	ID      string `json:"sub"`
	Session string `json:"https://ataper.net/session"`
	Role    string `json:"https://ataper.net/role"`

	Phone string `json:"https://ataper.net/phone"`
	Email string `json:"https://ataper.net/email"`

	Issuer string `json:"iss"`
}

func (a Authorization) Anonymous() bool {
	return a.ID == ""
}

func (a Authorization) Valid() error {
	return nil
}

type JWTParser interface {
}

type JWTGenerator interface {
	SignedString(key interface{}) (string, error)
}

// NewVerifyEndpoint returns a new HTTP handler for requests to the
// /v1/verify endpoint, which is used for forward-auth with traefik.
func NewVerifyEndpoint(
	serviceDomain string,
	jwtSigningSecret string,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("[INFO]", r.Method, r.URL.String())

		authHeader, ok := r.Header["Authorization"]
		if !ok || len(authHeader) == 0 {
			fmt.Println("[DETAIL]", "no authorization - issuing anonymous token")

			tokenString, err := jwt.NewWithClaims(
				jwt.GetSigningMethod(jwt.SigningMethodHS256.Alg()),
				generateAnonymousAuthorization(serviceDomain),
			).SignedString([]byte(jwtSigningSecret))
			if err != nil {
				fmt.Println("[ERROR]", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			err = json.NewEncoder(w).Encode(map[string]interface{}{
				"token": tokenString,
			})
			if err != nil {
				fmt.Println("[ERROR]", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			fmt.Println("[DETAIL]", "token issued")
			return
		}

		if !strings.HasPrefix(authHeader[0], "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader[0], "Bearer ")
		var auth Authorization
		_, err := jwt.ParseWithClaims(token, &auth, func(*jwt.Token) (interface{}, error) {
			return []byte(jwtSigningSecret), nil
		})
		if err != nil {
			fmt.Println("[ERROR]", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Println("[DETAIL]", "token has claims")
		spew.Dump(auth)

		fmt.Println("[DETAIL]", "passing request")
		setClaimHeaders(w, auth)
		w.WriteHeader(http.StatusOK)
	})
}

func generateAnonymousAuthorization(serviceDomain string) Authorization {
	return Authorization{
		Session: uuid.New().String(),
		Role:    "anonymous",
		Issuer:  serviceDomain,
	}
}

func setClaimHeaders(w http.ResponseWriter, a Authorization) {
	w.Header().Set("X-Ataper-Auth-Id", a.ID)
	w.Header().Set("X-Ataper-Auth-Session", a.Session)
	w.Header().Set("X-Ataper-Auth-Anonymous", strconv.FormatBool(a.Anonymous()))
	w.Header().Set("X-Ataper-Auth-Role", a.Role)
	w.Header().Set("X-Ataper-Auth-Issuer", a.Issuer)
	w.Header().Set("X-Ataper-Auth-Phone", a.Phone)
	w.Header().Set("X-Ataper-Auth-Email", a.Email)
}
