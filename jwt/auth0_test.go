package jwt_test

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/smartatransit/api-gateway/jwt"
	"github.com/smartatransit/api-gateway/jwt/jwtfakes"
)

var _ = Describe("Tokener", func() {
	var (
		doer *jwtfakes.FakeDoer
		t    jwt.Tokener
	)
	BeforeEach(func() {
		doer = &jwtfakes.FakeDoer{}
		t = jwt.NewTokener("url", "client", "secret", "audience", doer)

		doer.DoReturns(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"access_token": "my-fancy-access-token"}`)),
		}, nil)
	})
	Describe("GetToken", func() {
		var (
			token string
			err   error
		)
		JustBeforeEach(func() {
			token, err = t.GetToken(context.Background())
		})
		When("the request fails", func() {
			BeforeEach(func() {
				doer.DoReturns(nil, errors.New("request failed"))
			})
			It("fails", func() {
				Expect(err).To(MatchError("failed obtaining new access token: request failed"))
			})
		})
		When("the status code is non-normal", func() {
			BeforeEach(func() {
				doer.DoReturns(&http.Response{
					StatusCode: http.StatusFound,
					Body:       ioutil.NopCloser(strings.NewReader(`{"AT": "my-fancy-access-token"}`)),
				}, nil)
			})
			It("fails", func() {
				Expect(err).To(MatchError("failed obtaining new access token: status code 302"))
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
				Expect(err).To(MatchError("failed decoding new access token: unexpected EOF"))
			})
		})
		Context("otherwise", func() {
			It("succeeds", func() {
				Expect(err).To(BeNil())
				Expect(token).To(Equal("my-fancy-access-token"))
			})
		})
	})
})
