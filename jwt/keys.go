package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type Key struct {
	ID string `json:"kid"`

	Algorithm string `json:"alg"`
	KeyType   string `json:"kty"`

	RSAModulus         string `json:"n"`
	RSAExponent        string `json:"e"`
	RSAPrivateExponent string `json:"d"`
}

//go:generate counterfeiter . Keys
type Keys interface {
	Fetch(kid string) (jose.JSONWebKey, error)
}

//go:generate counterfeiter . Doer
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

func NewKeyServer(uri string, doer Doer) *KeyServer {
	return &KeyServer{
		keysURI:  uri,
		doer:     doer,
		cacheTTL: 15 * time.Minute,
	}
}

type KeyServer struct {
	keysURI string
	keys    map[string]jose.JSONWebKey
	doer    Doer

	cacheTTL             time.Duration
	lastFetchedTimestamp time.Time
}

var ErrUnrecognizedPublicKey = errors.New("unrecognized public key")

func (ks *KeyServer) Fetch(kid string) (jose.JSONWebKey, error) {
	_, ok := ks.keys[kid]
	if !ok || time.Since(ks.lastFetchedTimestamp) > ks.cacheTTL {
		if err := ks.refresh(); err != nil {
			return jose.JSONWebKey{}, err
		}
	}

	if key, ok := ks.keys[kid]; ok {
		return key, nil
	}

	return jose.JSONWebKey{}, ErrUnrecognizedPublicKey
}

type keysResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

func (ks *KeyServer) refresh() error {
	now := time.Now()

	req, _ := http.NewRequest("GET", ks.keysURI, nil)
	resp, err := ks.doer.Do(req)
	if err != nil {
		return fmt.Errorf("failed fetching JWKs: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed fetching JWKs: status code %v", resp.StatusCode)
	}

	var keys keysResponse
	if err = json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return fmt.Errorf("malformed JWK payload: %w", err)
	}

	newKeys := make(map[string]jose.JSONWebKey)
	for _, k := range keys.Keys {
		newKeys[k.KeyID] = k
	}

	ks.keys = newKeys
	ks.lastFetchedTimestamp = now
	return nil
}
