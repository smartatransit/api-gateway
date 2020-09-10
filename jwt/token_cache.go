package jwt

import (
	"context"
	"time"
)

// CachedToken represents a cached token
type CachedToken struct {
	token string
	expy  time.Time
}

// TokenCache parses a JWT into an Authorization struct
//go:generate counterfeiter . TokenCache
type TokenCache interface {
	FetchToken(ctx context.Context, key string) (string, bool)
	Clean(ctx context.Context)
	AddToken(ctx context.Context, key string, token string, expy time.Time)
}

// NewTokenCache creates a new TokenCache
func NewTokenCache() *TokenAgent {
	return &TokenAgent{
		tokens: map[string]CachedToken{},
	}
}

// TokenAgent implements TokenCache
type TokenAgent struct {
	tokens map[string]CachedToken
}

// FetchToken gets a token for the key if there is an unexpired one
func (a *TokenAgent) FetchToken(ctx context.Context, key string) (string, bool) {
	a.Clean(ctx)

	if v, ok := a.tokens[key]; ok {
		return v.token, true
	}
	return "", false
}

// Clean clears out any expired tokens
func (a *TokenAgent) Clean(ctx context.Context) {
	for k, v := range a.tokens {
		if time.Now().After(v.expy) {
			delete(a.tokens, k)
		}
	}
}

// AddToken adds a token to cache
func (a *TokenAgent) AddToken(ctx context.Context, key string, token string, expy time.Time) {
	a.tokens[key] = CachedToken{
		token: token,
		expy:  expy,
	}
}
