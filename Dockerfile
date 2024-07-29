# Builder image
FROM golang:1.21.12 as builder
WORKDIR /workspace

ENV GO111MODULE=on

COPY go.mod go.sum ./
RUN go mod download

ADD . .
RUN make build

# Runtime image
FROM alpine:3.20.2
WORKDIR /

COPY --from=builder /workspace/ipsec-prometheus-exporter .
ENTRYPOINT ["/ipsec-prometheus-exporter"]
