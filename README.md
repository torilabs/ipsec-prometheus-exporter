# IPsec Prometheus Exporter

_The IPsec Prometheus exporter subscribes to the strongSwan via Vici API and exposes [Security Associations](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-sa) (SAs) metrics._

Collected metrics (together with application metrics) are exposed on `/metrics` endpoint. Prometheus target is then configured with this endpoint and port e.g. `http://localhost:8079/metrics`.

## Configuration

IPsec Prometheus exporter is configured via command-line arguments. If not provided, the default values are used.

### Command-line arguments

If the default value match with your choice you can omit it.

```
# server port where the collected metrics are available
--server-port=8079

# logging level
--log-level=INFO

# Vici network scheme - tcp, udp or unix
--vici-network=tcp

# Vici address is the ip-address or hostname with port or unix socket path.
# IPv6 is supported. Use address in format of "[fd12:3456:789a::1]:4502".
--vici-address=localhost:4502
```

## Value Definition


| Metric | Value | Description |
|--------|-------|-------------|
| strongswan_*_status | 0 | The tunnel is installed and is up and running. |
| strongswan_*_status | 1 | The connection is established. |
| strongswan_*_status | 2 | The tunnel or connection is down. |
| strongswan_*_status | 3 | The tunnel or connection status is not recognized. |

## Build & Run
To build the binary run:
```bash
make build
```

Run the binary with optional arguments provided:
```bash
./ipsec-prometheus-exporter [--server-port=8079] [--log-level=INFO] [--vici-network=tcp] [--vici-address=localhost:4502]
```

## Docker image
Public docker image is available for multiple platforms: https://hub.docker.com/r/torilabs/ipsec-prometheus-exporter
```
docker run -it -p 8079:8079 --rm torilabs/ipsec-prometheus-exporter:latest --server-port=8079
```
