FROM golang:1.13 AS builder

WORKDIR /src
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/
COPY endpoint/ endpoint/
COPY main.go main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -a -installsuffix cgo -o api

FROM alpine:3.11
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/api /api
CMD ["/api"]
