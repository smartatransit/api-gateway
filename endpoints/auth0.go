package endpoints

// import (
// 	"context"
// 	"log"

// 	"golang.org/x/oauth2"

// 	oidc "github.com/coreos/go-oidc"
// )

// type Authenticator struct {
// 	Provider *oidc.Provider
// 	Config   oauth2.Config
// 	Ctx      context.Context
// }

// func NewAuthenticator(
// 	clientID string,
// 	clientSecret string,
// 	redirecURL string, // TODO
// ) (*Authenticator, error) {
// 	ctx := context.Background()

// 	provider, err := oidc.NewProvider(ctx, "https://dev-iz7rs90r.auth0.com/")
// 	if err != nil {
// 		log.Printf("failed to get provider: %v", err)
// 		return nil, err
// 	}

// 	conf := oauth2.Config{
// 		ClientID:     "36e3juMosN7NPDivUWoTddi6W51cYBzU",
// 		ClientSecret: "YOUR_CLIENT_SECRET",
// 		RedirectURL:  "http://localhost:3000/callback",
// 		Endpoint:     provider.Endpoint(),
// 		Scopes:       []string{oidc.ScopeOpenID, "profile"},
// 	}

// 	return &Authenticator{
// 		Provider: provider,
// 		Config:   conf,
// 		Ctx:      ctx,
// 	}, nil
// }
