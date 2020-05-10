package endpoint_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/smartatransit/api-gateway/endpoint"
	"github.com/smartatransit/api-gateway/jwt"
	"github.com/smartatransit/api-gateway/jwt/jwtfakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var _ = Describe("NewVerifyEndpoint", func() {
	var (
		parser *jwtfakes.FakeParser
		anon   *jwtfakes.FakeTokener

		r *http.Request
		w *httptest.ResponseRecorder

		resp *http.Response
	)

	BeforeEach(func() {
		parser = &jwtfakes.FakeParser{}
		anon = &jwtfakes.FakeTokener{}

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
		endpoint.NewVerifyEndpoint(parser, anon).
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
				"X-Ataper-Auth-Session": ConsistOf(Equal("Session-Value")),
				"X-Ataper-Auth-Role":    ConsistOf(Equal("Role-Value")),
			}))
		})
	})
})
