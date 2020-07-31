package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// Authorization is used to interact with the `jwt` package
type Authorization struct {
	Session string `json:"https://jwt.smartatransit.com/session"`
	Role    string `json:"https://jwt.smartatransit.com/role"`
}

// SetAuthHeaders converts the authorization claims into
// X-Smarta-Auth headers.
func (a Authorization) SetAuthHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Smarta-Auth-Session", a.Session)
	w.Header().Set("X-Smarta-Auth-Role", a.Role)
}

// Valid implements jwt.Authorization
func (a Authorization) Valid() error {
	return nil
}

// Parser parses a JWT into an Authorization struct
//go:generate counterfeiter . Parser
type Parser interface {
	ParseToken(ctx context.Context, tokenStr string) (Authorization, error)
}

// NewParser creates a new JWT parser
func NewParser(keys Keys) ParserAgent {
	return ParserAgent{
		keys:            keys,
		ParseWithClaims: jwt.ParseWithClaims,
	}
}

// ParserAgent implements Parser
type ParserAgent struct {
	keys            Keys
	ParseWithClaims ParseFunc
}

//go:generate counterfeiter . ParseFunc
type ParseFunc func(tokenString string, claims jwt.Claims, keyFunc jwt.Keyfunc) (*jwt.Token, error)

// ParseToken fails if the token is invalid, has an invalid signature, or fails
// standard claims validations. Otherwise, returns the claims covered by the
// Authorization struct. It uses the underlying Keys implementation to look up
// the `kid` in the key for verification.
func (a ParserAgent) ParseToken(ctx context.Context, tokenStr string) (Authorization, error) {
	var auth Authorization
	_, err := a.ParseWithClaims(tokenStr, &auth, a.keyFunc)
	if err != nil {
		return Authorization{}, fmt.Errorf("failed parsing JWT: %w", err)
	}

	return auth, nil
}

func (a ParserAgent) keyFunc(t *jwt.Token) (interface{}, error) {
	key, err := a.keys.Fetch(t.Header["kid"].(string))
	if err != nil {
		return nil, fmt.Errorf("failed fectching keys: %w", err)
	}

	if key.Algorithm != t.Header["alg"].(string) {
		return nil, errors.New("jwk algorithm didn't match")
	}

	return key.Key, nil
}
