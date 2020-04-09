package endpoint

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/smartatransit/api-gateway/jwt"
)

// NewVerifyEndpoint returns a new HTTP handler for requests to the
// /v1/verify endpoint, which is used for forward-auth with traefik.
func NewVerifyEndpoint(
	parser jwt.Parser,
	anon jwt.Tokener,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader, ok := r.Header["Authorization"]
		if !ok || len(authHeader) == 0 {
			tokenString, err := anon.GetToken(r.Context())
			if err != nil {
				fmt.Println("[ERROR]", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token": tokenString,
			})

			return
		}

		if !strings.HasPrefix(authHeader[0], "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		auth, err := parser.ParseToken(r.Context(), strings.TrimPrefix(authHeader[0], "Bearer "))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		auth.SetAuthHeaders(w)
		w.WriteHeader(http.StatusOK)
	})
}
