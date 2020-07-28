package jwt_test

import (
	"context"
	"errors"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	djwt "github.com/dgrijalva/jwt-go"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/smartatransit/api-gateway/jwt"
	"github.com/smartatransit/api-gateway/jwt/jwtfakes"
)

var _ = Describe("Parser", func() {
	var (
		keys      *jwtfakes.FakeKeys
		parseFunc *jwtfakes.FakeParseFunc

		parser jwt.ParserAgent
	)
	BeforeEach(func() {
		keys = &jwtfakes.FakeKeys{}
		keys.FetchReturns(jose.JSONWebKey{
			KeyID:     "my-kid",
			Algorithm: "rsa",
			Key:       "my-public-key",
		}, nil)

		parseFunc = &jwtfakes.FakeParseFunc{
			Stub: func(tokenString string, claims djwt.Claims, keyFunc djwt.Keyfunc) (*djwt.Token, error) {
				key, err := keyFunc(&djwt.Token{
					Header: map[string]interface{}{
						"kid": "token-kid",
						"alg": "rsa",
					},
				})
				if err != nil {
					return nil, err
				}

				Expect(key).To(Equal("my-public-key"))

				authPtr := claims.(*jwt.Authorization)
				authPtr.Role = "role-val"
				authPtr.Session = "sess-val"

				return nil, nil
			},
		}

		parser = jwt.NewParser(keys)
		parser.ParseWithClaims = parseFunc.Spy
	})
	Describe("ParseToken", func() {
		var (
			auth jwt.Authorization
			err  error
		)
		JustBeforeEach(func() {
			auth, err = parser.ParseToken(context.Background(), "requested-kid")
		})
		When("fetching the keys fails", func() {
			BeforeEach(func() {
				keys.FetchReturns(jose.JSONWebKey{}, errors.New("fetch failed"))
			})
			It("fails", func() {
				Expect(err).To(MatchError("failed parsing JWT: failed fectching keys: fetch failed"))
			})
		})
		When("the JWK algorithm doesn't match", func() {
			BeforeEach(func() {
				keys.FetchReturns(jose.JSONWebKey{
					Algorithm: "hmac",
				}, nil)
			})
			It("fails", func() {
				Expect(err).To(MatchError("failed parsing JWT: jwk algorithm didn't match"))
			})
		})
		Context("otherwise", func() {
			It("succeeds", func() {
				Expect(err).To(BeNil())
				Expect(auth.Session).To(Equal("sess-val"))
				Expect(auth.Role).To(Equal("role-val"))
			})
		})
	})
})

var _ = Describe("Authorization", func() {
	Describe("SetAuthHeaders", func() {
		It("works", func() {
			rw := httptest.NewRecorder()
			jwt.Authorization{
				Session: "sess",
				Role:    "role",
			}.SetAuthHeaders(rw)

			Expect(rw.Result().Header).To(MatchAllKeys(Keys{
				"X-Smarta-Auth-Session": ConsistOf("sess"),
				"X-Smarta-Auth-Role":    ConsistOf("role"),
			}))
		})
	})
	Describe("Valid", func() {
		It("returns nil", func() {
			Expect(jwt.Authorization{}.Valid()).To(BeNil())
		})
	})
})
