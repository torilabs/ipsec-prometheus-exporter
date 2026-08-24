# Builder image
FROM golang:1.25-alpine3.23@sha256:27b3069b25647beacd3745b0b2c83e2f9b8d3935455a32cd4531236ee1c960e0 AS builder
WORKDIR /workspace

ENV GO111MODULE=on

COPY go.mod go.sum ./
RUN go mod download
RUN apk add --no-cache make

ADD . .
RUN make build

# Runtime image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
WORKDIR /

COPY --from=builder /workspace/ipsec-prometheus-exporter .
ENTRYPOINT ["/ipsec-prometheus-exporter"]
