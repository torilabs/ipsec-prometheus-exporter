# Builder image
FROM golang:1.25-alpine3.23@sha256:60e626bbde32def8694687d03536ea4341b19e5f068e9a630225a1dfbd0505c9 AS builder
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
