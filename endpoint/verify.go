package endpoint

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/smartatransit/api-gateway/jwt"
)

// NewVerifyEndpoint returns a new HTTP handler for requests to the
// /v1/verify endpoint, which is used for forward-auth with traefik.
func NewVerifyEndpoint(
	logger *logrus.Logger,
	parser jwt.Parser,
	anon jwt.Tokener,
	tCache jwt.TokenCache,
	apiKeys jwt.TokenerFactory,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader, ok := r.Header["Authorization"]
		if !ok || len(authHeader) == 0 {
			tokenString, err := anon.GetToken(r.Context())
			if err != nil {
				logger.Errorf("failed to generate anonymous token: %s", err.Error())
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

		var key, token string
		if strings.HasPrefix(authHeader[0], "Key ") {
			key = strings.TrimPrefix(authHeader[0], "Key ")
			var ok bool
			if token, ok = tCache.FetchToken(r.Context(), key); !ok {
				results := regexp.MustCompile(`^([^|]+)\|([^|]+)$`).FindStringSubmatch(key)
				if len(results) == 0 {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				clientID := results[1]
				clientSecret := results[2]

				var err error
				token, err = apiKeys(clientID, clientSecret).GetToken(r.Context())
				if err != nil {
					logger.Errorf("failed to generate API key token for client `%s`: %s", clientID, err.Error())
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
		} else {
			if !strings.HasPrefix(authHeader[0], "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			token = strings.TrimPrefix(authHeader[0], "Bearer ")
		}

		auth, err := parser.ParseToken(r.Context(), token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if len(key) > 0 {
			// If this token was obtained from a key, let's go ahead and save it to the cache
			// (now that we've parsed it and know when it will expire).
			tCache.AddToken(r.Context(), key, token, time.Unix(auth.StandardClaims.ExpiresAt, 0).UTC())
		}

		auth.SetAuthHeaders(w)
		w.WriteHeader(http.StatusOK)
	})
}
