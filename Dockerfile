# Builder image
FROM golang:1.23.4 AS builder
WORKDIR /workspace

ENV GO111MODULE=on

COPY go.mod go.sum ./
RUN go mod download

ADD . .
RUN make build

# Runtime image
FROM alpine:3.21.2
WORKDIR /

COPY --from=builder /workspace/ipsec-prometheus-exporter .
ENTRYPOINT ["/ipsec-prometheus-exporter"]
