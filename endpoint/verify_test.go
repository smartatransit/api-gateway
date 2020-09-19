package endpoint_test

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"

	"github.com/sirupsen/logrus"
	"github.com/smartatransit/api-gateway/endpoint"
	"github.com/smartatransit/api-gateway/jwt"
	"github.com/smartatransit/api-gateway/jwt/jwtfakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var _ = Describe("NewVerifyEndpoint", func() {
	var (
		log    *logrus.Logger
		parser *jwtfakes.FakeParser
		anon   *jwtfakes.FakeTokener
		fact   *jwtfakes.FakeTokenerFactory
		tCache *jwtfakes.FakeTokenCache

		r *http.Request
		w *httptest.ResponseRecorder

		resp *http.Response
	)

	BeforeEach(func() {
		parser = &jwtfakes.FakeParser{}
		anon = &jwtfakes.FakeTokener{}
		fact = &jwtfakes.FakeTokenerFactory{}
		tCache = &jwtfakes.FakeTokenCache{}

		log = logrus.New()
		log.SetOutput(ioutil.Discard)

		anon.GetTokenReturns("good-token", nil)
		parser.ParseTokenReturns(jwt.Authorization{
			Session: "Session-Value",
			Role:    "Role-Value",
		}, nil)

		r, _ = http.NewRequest("GET", "/path", nil)
		r.Header.Set("Authorization", "Bearer token")
		w = httptest.NewRecorder()
	})

	JustBeforeEach(func() {
		endpoint.NewVerifyEndpoint(log, parser, anon, tCache, fact.Spy).
			ServeHTTP(w, r)

		resp = w.Result()
	})

	When("there is no Authorization header", func() {
		BeforeEach(func() {
			r.Header.Del("Authorization")
		})
		When("when fetching the anonymous token fails", func() {
			BeforeEach(func() {
				anon.GetTokenReturns("", errors.New("failed fetching token"))
			})
			It("fails", func() {
				Expect(resp.StatusCode).To(Equal(http.StatusInternalServerError))
			})
		})
		When("all goes well", func() {
			It("returns a new anonymous token", func() {
				var body = map[string]string{}
				Expect(json.NewDecoder(resp.Body).Decode(&body)).To(BeNil())

				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
				Expect(body["token"]).To(Equal("good-token"))
			})
		})
	})
	When("there's a Key schema", func() {
		When("it's malformed", func() {
			BeforeEach(func() {
				r.Header.Set("Authorization", "Key token")
			})
			It("fails", func() {
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
			})
		})
		When("there's no cached token, and the Auth0 request fails", func() {
			BeforeEach(func() {
				r.Header.Set("Authorization", "Key id|secret")
			})
			BeforeEach(func() {
				tokener := &jwtfakes.FakeTokener{}
				tokener.GetTokenReturns("", errors.New("get token failed"))

				fact.Returns(tokener)
			})
			It("fails", func() {
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
				id, secret := fact.ArgsForCall(0)
				Expect(id).To(Equal("id"))
				Expect(secret).To(Equal("secret"))
			})
		})
		When("all goes well", func() {
			BeforeEach(func() {
				r.Header.Set("Authorization", "Key id|secret")

				tokener := &jwtfakes.FakeTokener{}
				tokener.GetTokenReturns("my-special-token", nil)

				fact.Returns(tokener)
			})
			It("succeeds", func() {
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				id, secret := fact.ArgsForCall(0)
				Expect(id).To(Equal("id"))
				Expect(secret).To(Equal("secret"))

				_, token := parser.ParseTokenArgsForCall(0)
				Expect(token).To(Equal("my-special-token"))
			})
		})
	})
	When("the Bearer schema is malformed", func() {
		BeforeEach(func() {
			r.Header.Set("Authorization", "Bear token")
		})
		It("fails", func() {
			Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
		})
	})
	When("the token is malformed or has a bad signature", func() {
		BeforeEach(func() {
			parser.ParseTokenReturns(jwt.Authorization{}, errors.New("parse failed"))
		})
		It("fails", func() {
			Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
		})
	})
	Context("otherwise", func() {
		It("calls SetAuthHeaders and then response with OK", func() {
			Expect(resp.Header).To(MatchKeys(IgnoreExtras, Keys{
				"X-Smarta-Auth-Session": ConsistOf(Equal("Session-Value")),
				"X-Smarta-Auth-Role":    ConsistOf(Equal("Role-Value")),
			}))
		})
	})
})
