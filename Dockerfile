# Builder image
FROM golang:1.26-alpine3.24@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS builder
WORKDIR /workspace

ENV GO111MODULE=on

COPY go.mod go.sum ./
RUN go mod download
RUN apk add --no-cache make

ADD . .
RUN make build

# Runtime image
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
WORKDIR /

COPY --from=builder /workspace/ipsec-prometheus-exporter .
ENTRYPOINT ["/ipsec-prometheus-exporter"]
