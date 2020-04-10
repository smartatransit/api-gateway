package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Tokener is an interface for obtaining tokens
//go:generate counterfeiter . Tokener
type Tokener interface {
	GetToken(ctx context.Context) (string, error)
}

// Auth0Tokener implements anonymizer by requesting new tokens
// through an Auth0 machine-to-machine client
type Auth0Tokener struct {
	url     string
	payload string
	doer    Doer
}

// NewTokener builds an Auth0Tokener from the specified auth0
// API url, client id, and secret.
func NewTokener(url, clientID, clientSecret, audience string, doer Doer) Auth0Tokener {
	buf := bytes.NewBuffer(nil)
	_ = json.NewEncoder(buf).Encode(map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"audience":      audience,
		"grant_type":    "client_credentials",
	})

	return Auth0Tokener{
		url:     url,
		doer:    doer,
		payload: buf.String(),
	}
}

type tokenResponse struct {
	AT string `json:"access_token"`
}

// GetToken returns an token from the auth0 client
func (a Auth0Tokener) GetToken(ctx context.Context) (string, error) {
	req, _ := http.NewRequest("POST", a.url, strings.NewReader(a.payload))
	req.Header.Add("content-type", "application/json")

	resp, err := a.doer.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed obtaining new access token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed obtaining new access token: status code %v", resp.StatusCode)
	}

	var tr tokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tr)
	if err != nil {
		return "", fmt.Errorf("failed decoding new access token: %w", err)
	}

	return tr.AT, nil
}
