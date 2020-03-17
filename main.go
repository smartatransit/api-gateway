package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/jessevdk/go-flags"
	"github.com/smartatransit/api-gateway/endpoint"
)

var options struct {
	JWTSigningSecret string `long:"jwt-signing-secret" env:"JWT_SIGNING_SECRET" required:"true"`
	ServiceDomain    string `long:"service-domain" env:"SERVICE_DOMAIN" required:"true"`

	Port int `long:"port" env:"PORT" default:"8080"`
}

func main() {
	_, err := flags.Parse(&options)
	if err != nil {
		log.Fatal(err)
	}

	// NOTE: this service will receive requests forwarded from traefik, which were intended for
	// other services. The `path` on the request will be the path of the _original_ request, so
	// we listen for all requests on all paths, and always treat them the same.
	http.Handle("/", endpoint.NewVerifyEndpoint(options.ServiceDomain, options.JWTSigningSecret))

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", options.Port), nil))
}
