package jwt_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/smartatransit/api-gateway/jwt"
)

var _ = Describe("TokenCache", func() {
	var (
		tc *jwt.TokenAgent
	)
	BeforeEach(func() {
		tc = jwt.NewTokenCache()
	})
	Describe("FetchToken", func() {
		var (
			token string
			ok    bool
		)
		JustBeforeEach(func() {
			token, ok = tc.FetchToken(context.Background(), "my-api-key")
		})
		When("there's no match", func() {
			It("fails", func() {
				Expect(ok).To(BeFalse())
			})
		})
		When("there's a match", func() {
			BeforeEach(func() {
				tc.AddToken(context.Background(), "my-api-key", "my-token", time.Now().Add(time.Hour))
			})
			It("fails", func() {
				Expect(ok).To(BeTrue())
				Expect(token).To(Equal("my-token"))
			})
		})
	})
	Describe("Clean", func() {
		It("works", func() {
			_, ok := tc.FetchToken(context.Background(), "my-api-key")
			Expect(ok).To(BeFalse())
			tc.AddToken(context.Background(), "my-api-key", "my-token", time.Now().Add(time.Second))

			_, ok = tc.FetchToken(context.Background(), "my-api-key")
			Expect(ok).To(BeTrue())

			time.Sleep(2 * time.Second)

			_, ok = tc.FetchToken(context.Background(), "my-api-key")
			Expect(ok).To(BeFalse())
		})
	})
})
