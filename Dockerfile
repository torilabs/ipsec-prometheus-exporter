# Builder image
FROM golang:1.27-alpine3.24@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS builder
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
