package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/jessevdk/go-flags"
	"github.com/smartatransit/api-gateway/endpoints"
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

	http.Handle("/v1/verify", endpoints.NewVerifyEndpoint(options.ServiceDomain, options.JWTSigningSecret))

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", options.Port), nil))
}
