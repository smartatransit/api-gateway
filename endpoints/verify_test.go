package endpoints_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"github.com/smartatransit/api-gateway/endpoints"
)

var _ = Describe("NewVerifyEndpoint", func() {
	var (
		r *http.Request
		w *httptest.ResponseRecorder

		auth *endpoints.Authorization

		resp *http.Response
	)

	BeforeEach(func() {
		r, _ = http.NewRequest("GET", "/path", nil)
		w = httptest.NewRecorder()

		auth = &endpoints.Authorization{
			ID:      "ID-Value",
			Session: "Session-Value",
			Role:    "Role-Value",
			Phone:   "Phone-Value",
			Email:   "Email-Value",
			Issuer:  "Issuer-Value",
		}
	})

	JustBeforeEach(func() {
		if auth != nil {
			tokenString, err := jwt.NewWithClaims(
				jwt.GetSigningMethod(jwt.SigningMethodHS256.Alg()),
				auth,
			).SignedString([]byte("secret"))
			Expect(err).To(BeNil())

			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenString))
		}

		endpoints.NewVerifyEndpoint("api-gateway.example.com", "secret").
			ServeHTTP(w, r)

		resp = w.Result()
	})

	When("there is no Authorization header", func() {
		BeforeEach(func() {
			auth = nil
			r.Header.Del("Authorization")
		})
		When("when generating the anonymous token fails", func() {
			// NOTE inaccessible
		})
		When("when the new token can't be written to the response", func() {
			// NOTE inaccessible
		})
		When("all goes well", func() {
			It("returns a new anonymous token", func() {
				var body = map[string]string{}
				Expect(json.NewDecoder(resp.Body).Decode(&body)).To(BeNil())

				var auth endpoints.Authorization
				_, err := jwt.ParseWithClaims(body["token"], &auth, func(*jwt.Token) (interface{}, error) {
					return []byte("secret"), nil
				})
				Expect(err).To(BeNil())

				Expect(auth).To(MatchAllFields(Fields{
					"ID":      BeEmpty(),
					"Session": MatchRegexp("[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{12}"),
					"Role":    Equal("anonymous"),
					"Phone":   BeEmpty(),
					"Email":   BeEmpty(),
					"Issuer":  Equal("api-gateway.example.com"),
				}))
			})
		})
	})
	When("the Bearer schema is malformed", func() {
		// TODO
	})
	When("the token is malformed or has a bad signature", func() {
		// TODO
	})
	Context("otherwise", func() {
		It("responds with the correct X-Ataper-Auth-* headers", func() {
			Expect(resp.Header).To(MatchKeys(IgnoreExtras, Keys{
				"X-Ataper-Auth-Id":        ConsistOf(Equal("ID-Value")),
				"X-Ataper-Auth-Session":   ConsistOf(Equal("Session-Value")),
				"X-Ataper-Auth-Anonymous": ConsistOf(Equal("false")),
				"X-Ataper-Auth-Role":      ConsistOf(Equal("Role-Value")),
				"X-Ataper-Auth-Issuer":    ConsistOf(Equal("Issuer-Value")),
				"X-Ataper-Auth-Phone":     ConsistOf(Equal("Phone-Value")),
				"X-Ataper-Auth-Email":     ConsistOf(Equal("Email-Value")),
			}))
		})
		When("when the token is anonymous", func() {
			BeforeEach(func() {
				auth.ID = ""
			})
			It("responds with the correct X-Ataper-Auth-* headers", func() {
				Expect(resp.Header).To(MatchKeys(IgnoreExtras, Keys{
					"X-Ataper-Auth-Id":        ConsistOf(Equal("")),
					"X-Ataper-Auth-Session":   ConsistOf(Equal("Session-Value")),
					"X-Ataper-Auth-Anonymous": ConsistOf(Equal("true")),
					"X-Ataper-Auth-Role":      ConsistOf(Equal("Role-Value")),
					"X-Ataper-Auth-Issuer":    ConsistOf(Equal("Issuer-Value")),
					"X-Ataper-Auth-Phone":     ConsistOf(Equal("Phone-Value")),
					"X-Ataper-Auth-Email":     ConsistOf(Equal("Email-Value")),
				}))
			})
		})
	})
})
