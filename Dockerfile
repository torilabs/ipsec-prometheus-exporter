# Builder image
FROM golang:1.24.4 AS builder
WORKDIR /workspace

ENV GO111MODULE=on

COPY go.mod go.sum ./
RUN go mod download

ADD . .
RUN make build

# Runtime image
FROM alpine:3.22.0
WORKDIR /

COPY --from=builder /workspace/ipsec-prometheus-exporter .
ENTRYPOINT ["/ipsec-prometheus-exporter"]
