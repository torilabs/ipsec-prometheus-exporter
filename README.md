# IPsec Prometheus Exporter

_The IPsec Prometheus exporter subscribes to the strongSwan via Vici API and exposes [Security Associations](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-sa) (SAs) metrics._

Collected metrics (together with application metrics) are exposed on `/metrics` endpoint. Prometheus target is then configured with this endpoint and port e.g. `http://localhost:8079/metrics`.

## Configuration

IPsec Prometheus exporter configuration yaml file is optional. If not provided, the default values are used.

### Config file

If the default value match with your choice you can omit it.

```yaml
# Logger configuration
logging:
  # logging level - default: INFO
  level: DEBUG

# HTTP server configuration
server:
  # server port - default: 8079
  port: 8080

# Vici configuration
vici:
  # Vici network scheme - default: tcp
  network: "udp"
  # Vici host is the ip-address or hostname.
  # Default values for hostname is "localhost".
  # IPv6 is supported. Use host in format of "[fd12:3456:789a::1]".
  host: "127.0.0.1"
  # Vici port - default: 4502
  port: 30123
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

Run the binary with optional `config` parameter provided:
```bash
./ipsec-prometheus-exporter [--config=<path to yaml config file>]
```

## Docker image
Public docker image is available for multiple platforms: https://hub.docker.com/r/torilabs/ipsec-prometheus-exporter
```
docker run -it -p 8079:8079 -v $(pwd)/my-config.yaml:/config.yaml --rm torilabs/ipsec-prometheus-exporter:latest
```
