# Builder image
FROM golang:1.26-alpine3.23@sha256:0525c952defebc693cdaf62cdf43afa32be5a7f377e99260642ea19c240c708e AS builder
WORKDIR /workspace

ENV GO111MODULE=on

COPY go.mod go.sum ./
RUN go mod download
RUN apk add --no-cache make

ADD . .
RUN make build

# Runtime image
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
WORKDIR /

COPY --from=builder /workspace/ipsec-prometheus-exporter .
ENTRYPOINT ["/ipsec-prometheus-exporter"]
