package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/jessevdk/go-flags"
	"github.com/smartatransit/api-gateway/endpoint"
	"github.com/smartatransit/api-gateway/jwt"
)

var options struct {
	Auth0TenantURL      string `long:"auth0-tenant-url" env:"AUTH0_TENANT_URL" required:"true"`
	ClientID            string `long:"client-id" env:"CLIENT_ID" required:"true"`
	ClientSecret        string `long:"client-secret" env:"CLIENT_SECRET" required:"true"`
	Auth0ClientAudience string `long:"auth0-client-audience" env:"AUTH0_CLIENT_AUDIENCE" required:"true"`

	Port int `long:"port" env:"PORT" default:"8080"`
}

func main() {
	_, err := flags.Parse(&options)
	if err != nil {
		log.Fatal(err)
	}

	keys := jwt.NewKeyServer(
		options.Auth0TenantURL+"/.well-known/jwks.json",
		http.DefaultClient,
	)
	parser := jwt.NewParser(keys)
	anonymizer := jwt.NewTokener(
		options.Auth0TenantURL+"/oauth/token",
		options.ClientID,
		options.ClientSecret,
		options.Auth0ClientAudience,
	)

	// NOTE: this service will receive requests forwarded from traefik, which were intended for
	// other services. The `path` on the request will be the path of the _original_ request, so
	// we listen for all requests on all paths, and always treat them the same.
	http.Handle("/", endpoint.NewVerifyEndpoint(parser, anonymizer))

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", options.Port), nil))
}
