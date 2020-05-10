package jwt_test

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/smartatransit/api-gateway/jwt"
	"github.com/smartatransit/api-gateway/jwt/jwtfakes"
	jose "gopkg.in/square/go-jose.v2"
)

var _ = Describe("KeyServer", func() {
	var (
		doer *jwtfakes.FakeDoer
		ks   *jwt.KeyServer
	)
	BeforeEach(func() {
		doer = &jwtfakes.FakeDoer{}

		doer.DoReturns(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"keys": [{"kid": "requested-kid", "kty": "RSA",   "n"   : "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w", "e"   : "AQAB"}]}`)),
		}, nil)
	})
	JustBeforeEach(func() {
		ks = jwt.NewKeyServer("uri", doer)
	})
	Describe("Fetch", func() {
		var (
			jwk jose.JSONWebKey
			err error
		)
		JustBeforeEach(func() {
			jwk, err = ks.Fetch("requested-kid")
		})
		When("a refresh is required", func() {
			When("the request fails", func() {
				BeforeEach(func() {
					doer.DoReturns(nil, errors.New("request failed"))
				})
				It("fails", func() {
					Expect(err).To(MatchError("failed fetching JWKs: request failed"))
				})
			})
			When("the status code is non-normal", func() {
				BeforeEach(func() {
					doer.DoReturns(&http.Response{
						StatusCode: http.StatusFound,
					}, nil)
				})
				It("fails", func() {
					Expect(err).To(MatchError("failed fetching JWKs: status code 302"))
				})
			})
			When("the response can't be decoded", func() {
				BeforeEach(func() {
					doer.DoReturns(&http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(strings.NewReader(`{`)),
					}, nil)
				})
				It("fails", func() {
					Expect(err).To(MatchError("malformed JWK payload: unexpected EOF"))
				})
			})
			When("the key still isn't found", func() {
				BeforeEach(func() {
					doer.DoReturns(&http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(strings.NewReader(`{"keys": [{"kid": "the-wrong-kid", "kty": "RSA",   "n"   : "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w", "e"   : "AQAB"}]}`)),
					}, nil)
				})
				It("fails", func() {
					Expect(err).To(MatchError("unrecognized public key"))
				})
			})
		})
		When("the key is known", func() {
			It("succeeds", func() {
				Expect(err).To(BeNil())
				Expect(jwk.KeyID).To(Equal("requested-kid"))
			})
		})
	})
})
