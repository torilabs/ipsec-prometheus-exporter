# IPSec Prometheus Exporter

_The IPSec Prometheus exporter subscribes to the strongSwan via Vici API and
exposes [Security Associations (SAs)[strongswan-sa] metrics. Optionally [X509 certificate][strongswan-x509] 
and [connection configuration][strongswan-conn] metrics can be turned on.

Collected metrics (together with application metrics) are exposed on
`/metrics` endpoint. Prometheus target is then configured with this endpoint
and port e.g. `http://localhost:8079/metrics`.

## Configuration

IPSec Prometheus exporter is configured via command-line arguments. If not
provided, the default values are used.

### Command-line arguments

If the default value match with your choice you can omit it.

```
Options and default values:
--server-port=8079              Application listen port where the collected metrics are available
--server-host=""                Application listen host where the collected metrics are available (empty for all hosts)
--log-level=info                Logging level (debug, info, warn, error)
--vici-network=tcp              Vici network scheme (tcp, udp, unix)
--vici-address=localhost:4502   IP address or hostname with a port or unix socket path
                                IPv6 is supported. Use address in format of "[fd12:3456:789a::1]:4502"
--enable-cert-metrics=false     Enable collecting of X509 certificate metrics (true, false)
--enable-conn-metrics=false     Enable collecting of connection configuration metrics (true, false)
```

## Metrics

### Security Associations

Always collected, from the Vici [`list-sas`][strongswan-list-sa] command.

| Metric                                  | Labels                                                                    | Description                                                         |
|-----------------------------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------|
| `strongswan_ike_count`                  | –                                                                         | Number of known IKE SAs                                             |
| `strongswan_ike_info`                   | `ike_name`, `ike_id`, `local_id`, `remote_id`, `remote_host`              | Always `1`; carries the IKE identities and the peer address         |
| `strongswan_ike_version`                | `ike_name`, `ike_id`                                                      | IKE version                                                         |
| `strongswan_ike_status`                 | `ike_name`, `ike_id`                                                      | See [Status values](#status-values)                                 |
| `strongswan_ike_initiator`              | `ike_name`, `ike_id`                                                      | `1` if the local side initiated the IKE SA                          |
| `strongswan_ike_nat_local`              | `ike_name`, `ike_id`                                                      | `1` if the local endpoint is behind NAT                             |
| `strongswan_ike_nat_remote`             | `ike_name`, `ike_id`                                                      | `1` if the remote endpoint is behind NAT                            |
| `strongswan_ike_nat_fake`               | `ike_name`, `ike_id`                                                      | `1` if the NAT situation has been faked as responder                |
| `strongswan_ike_nat_any`                | `ike_name`, `ike_id`                                                      | `1` if any endpoint is behind NAT (also if faked)                   |
| `strongswan_ike_encryption_key_size`    | `ike_name`, `ike_id`, `algorithm`, `dh_group`                             | Key size of the encryption algorithm                                |
| `strongswan_ike_integrity_key_size`     | `ike_name`, `ike_id`, `algorithm`, `dh_group`                             | Key size of the integrity algorithm                                 |
| `strongswan_ike_established_seconds`    | `ike_name`, `ike_id`                                                      | Seconds since the IKE SA was established                            |
| `strongswan_ike_rekey_seconds`          | `ike_name`, `ike_id`                                                      | Seconds until the IKE SA is rekeyed                                 |
| `strongswan_ike_reauth_seconds`         | `ike_name`, `ike_id`                                                      | Seconds until the IKE SA is reauthenticated                         |
| `strongswan_ike_children_size`          | `ike_name`, `ike_id`                                                      | Number of child SAs of the IKE SA                                   |
| `strongswan_sa_status`                  | `ike_name`, `ike_id`, `child_name`, `child_id`, `local_ts`, `remote_ts`   | See [Status values](#status-values)                                 |
| `strongswan_sa_encap`                   | `ike_name`, `ike_id`, `child_name`, `child_id`                            | `1` if packets are forced into UDP encapsulation                    |
| `strongswan_sa_encryption_key_size`     | `ike_name`, `ike_id`, `child_name`, `child_id`, `algorithm`, `dh_group`   | Key size of the encryption algorithm                                |
| `strongswan_sa_integrity_key_size`      | `ike_name`, `ike_id`, `child_name`, `child_id`, `algorithm`, `dh_group`   | Key size of the integrity algorithm                                 |
| `strongswan_sa_inbound_bytes`           | `ike_name`, `ike_id`, `child_name`, `child_id`, `local_ts`, `remote_ts`   | Bytes received                                                      |
| `strongswan_sa_inbound_packets`         | `ike_name`, `ike_id`, `child_name`, `child_id`, `local_ts`, `remote_ts`   | Packets received                                                    |
| `strongswan_sa_last_inbound_seconds`    | `ike_name`, `ike_id`, `child_name`, `child_id`, `local_ts`, `remote_ts`   | Seconds since the last inbound packet                               |
| `strongswan_sa_outbound_bytes`          | `ike_name`, `ike_id`, `child_name`, `child_id`, `local_ts`, `remote_ts`   | Bytes sent                                                          |
| `strongswan_sa_outbound_packets`        | `ike_name`, `ike_id`, `child_name`, `child_id`, `local_ts`, `remote_ts`   | Packets sent                                                        |
| `strongswan_sa_last_outbound_seconds`   | `ike_name`, `ike_id`, `child_name`, `child_id`, `local_ts`, `remote_ts`   | Seconds since the last outbound packet                              |
| `strongswan_sa_established_seconds`     | `ike_name`, `ike_id`, `child_name`, `child_id`                            | Seconds since the child SA was installed                            |
| `strongswan_sa_rekey_seconds`           | `ike_name`, `ike_id`, `child_name`, `child_id`                            | Seconds until the child SA is rekeyed                               |
| `strongswan_sa_lifetime_seconds`        | `ike_name`, `ike_id`, `child_name`, `child_id`                            | Seconds until the child SA lifetime expires                         |

### X509 certificates

Collected with `--enable-cert-metrics=true`, from the Vici
[`list-certs`](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-certs)
command.

| Metric                        | Labels                                                  | Description                                  |
|-------------------------------|---------------------------------------------------------|----------------------------------------------|
| `strongswan_cert_count`       | –                                                       | Number of X509 certificates                  |
| `strongswan_cert_valid`       | `serial_number`, `subject`, `not_before`, `not_after`   | `1` if the certificate is currently valid    |
| `strongswan_cert_expire_secs` | `serial_number`, `subject`, `not_before`, `not_after`   | Seconds until the certificate expires        |

### Connections

Collected with `--enable-conn-metrics=true`, from the Vici
[`list-conns`](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-conn)
command. Interval metrics are only exported when the interval is configured.

| Metric                                | Labels                              | Description                                   |
|---------------------------------------|-------------------------------------|-----------------------------------------------|
| `strongswan_conn_count`               | –                                   | Number of loaded connections                  |
| `strongswan_conn_version`             | `conn_name`, `version`              | Always `1`; `version` is the IKE version      |
| `strongswan_conn_reauth_time`         | `conn_name`                         | IKE SA reauthentication interval in seconds   |
| `strongswan_conn_rekey_time`          | `conn_name`                         | IKE SA rekeying interval in seconds           |
| `strongswan_conn_child_count`         | `conn_name`                         | Number of child SA configurations             |
| `strongswan_conn_child_rekey_time`    | `conn_name`, `child_name`, `mode`   | Child SA rekeying interval in seconds         |
| `strongswan_conn_child_rekey_bytes`   | `conn_name`, `child_name`, `mode`   | Child SA rekeying interval in bytes           |
| `strongswan_conn_child_rekey_packets` | `conn_name`, `child_name`, `mode`   | Child SA rekeying interval in packets         |

### Labels

| Label                     | Meaning                                                                                                    |
|---------------------------|------------------------------------------------------------------------------------------------------------|
| `ike_name`                | Name of the connection the IKE SA belongs to                                                               |
| `ike_id`                  | strongSwan's `uniqueid` of the IKE SA; a reconnecting peer gets a new one                                  |
| `local_id`, `remote_id`   | IKE identities of the local and the remote side                                                            |
| `remote_host`             | Address of the remote peer; behind NAT this is the public address and may change during the IKE SA        |
| `child_name`, `child_id`  | Name and `uniqueid` of the child SA                                                                        |
| `local_ts`, `remote_ts`   | Traffic selectors of the child SA, multiple selectors joined with `;`                                      |

### Status values

| Metric                | Value | Description                                        |
|-----------------------|-------|----------------------------------------------------|
| `strongswan_*_status` | 0     | The tunnel is installed and is up and running.     |
| `strongswan_*_status` | 1     | The connection is established.                     |
| `strongswan_*_status` | 2     | The tunnel or connection is down.                  |
| `strongswan_*_status` | 3     | The tunnel or connection status is not recognized. |

### Query examples

`strongswan_ike_info` carries the identities once per IKE SA. Join it on
`ike_name` and `ike_id` to put them on any `strongswan_ike_*` or
`strongswan_sa_*` metric.

Remote identities currently connected via the connection `aps`:

```promql
strongswan_ike_info{ike_name="aps"}
```

Inbound traffic per remote identity:

```promql
sum by (remote_id) (
  rate(strongswan_sa_inbound_bytes[5m])
  * on (ike_name, ike_id) group_left (remote_id)
  strongswan_ike_info
)
```

Child SA status with the remote identity and address:

```promql
strongswan_sa_status
* on (ike_name, ike_id) group_left (remote_id, remote_host)
strongswan_ike_info
```

## Build & Run
To build the binary run:
```bash
make build
```

Run the binary with optional arguments provided:
```bash
./ipsec-prometheus-exporter [--server-port=8079] [--server-host=""] [--log-level=info] [--vici-network=tcp] [--vici-address=localhost:4502] [--enable-cert-metrics=false] [--enable-conn-metrics=false]
```

## Docker image
Public docker image is available for multiple platforms:
https://hub.docker.com/r/torilabs/ipsec-prometheus-exporter
```
docker run -it -p 8079:8079 --rm torilabs/ipsec-prometheus-exporter:latest --server-port=8079
```


## References

[strongswan-sa]: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-sa
[strongswan-x509]: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-certs
[strongswan-conn]: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-conn
[strongswan-list-sa]: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-sa

