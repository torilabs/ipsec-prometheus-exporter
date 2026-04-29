package strongswan

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/strongswan/govici/vici"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
)

type ConnsCollector struct {
	viciClientFn viciClientFn

	connCnt               *prometheus.Desc
	connVersion           *prometheus.Desc
	connReauthTime        *prometheus.Desc
	connRekeyTime         *prometheus.Desc
	connChildCnt          *prometheus.Desc
	connChildRekeyTime    *prometheus.Desc
	connChildRekeyBytes   *prometheus.Desc
	connChildRekeyPackets *prometheus.Desc
}

func NewConnsCollector(prefix string, viciClientFn viciClientFn) prometheus.Collector {
	return &ConnsCollector{
		viciClientFn: viciClientFn,

		connCnt: prometheus.NewDesc(
			prefix+"conn_count",
			"Number of loaded connections",
			nil, nil,
		),
		connVersion: prometheus.NewDesc(
			prefix+"conn_version",
			"IKE version for connection",
			[]string{"conn_name", "version"}, nil,
		),
		connReauthTime: prometheus.NewDesc(
			prefix+"conn_reauth_time",
			"IKE_SA reauthentication interval in seconds",
			[]string{"conn_name"}, nil,
		),
		connRekeyTime: prometheus.NewDesc(
			prefix+"conn_rekey_time",
			"IKE_SA rekeying interval in seconds",
			[]string{"conn_name"}, nil,
		),
		connChildCnt: prometheus.NewDesc(
			prefix+"conn_child_count",
			"Number of CHILD_SA configurations",
			[]string{"conn_name"}, nil,
		),
		connChildRekeyTime: prometheus.NewDesc(
			prefix+"conn_child_rekey_time",
			"CHILD_SA rekeying interval in seconds",
			[]string{"conn_name", "child_name", "mode"}, nil,
		),
		connChildRekeyBytes: prometheus.NewDesc(
			prefix+"conn_child_rekey_bytes",
			"CHILD_SA rekeying interval in bytes",
			[]string{"conn_name", "child_name", "mode"}, nil,
		),
		connChildRekeyPackets: prometheus.NewDesc(
			prefix+"conn_child_rekey_packets",
			"CHILD_SA rekeying interval in packets",
			[]string{"conn_name", "child_name", "mode"}, nil,
		),
	}
}

func (c *ConnsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.connCnt
	ch <- c.connVersion
	ch <- c.connReauthTime
	ch <- c.connRekeyTime
	ch <- c.connChildCnt
	ch <- c.connChildRekeyTime
	ch <- c.connChildRekeyBytes
	ch <- c.connChildRekeyPackets
}

func (c *ConnsCollector) Collect(ch chan<- prometheus.Metric) {
	conns, err := c.listConns()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			c.connCnt,
			prometheus.GaugeValue,
			float64(0),
		)
		return
	}
	ch <- prometheus.MustNewConstMetric(
		c.connCnt,
		prometheus.GaugeValue,
		float64(len(conns)),
	)
	c.collectConnMetrics(conns, ch)
}

func (c *ConnsCollector) collectConnMetrics(conns []Conn, ch chan<- prometheus.Metric) {
	for _, conn := range conns {
		// Connection version metric
		version := conn.Version
		if version == "" {
			version = "0"
		}
		ch <- prometheus.MustNewConstMetric(
			c.connVersion,
			prometheus.GaugeValue,
			1,
			conn.Name, version,
		)

		// Connection reauth time
		if conn.ReauthTime > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.connReauthTime,
				prometheus.GaugeValue,
				float64(conn.ReauthTime),
				conn.Name,
			)
		}

		// Connection rekey time
		if conn.RekeyTime > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.connRekeyTime,
				prometheus.GaugeValue,
				float64(conn.RekeyTime),
				conn.Name,
			)
		}

		// Child SA count
		ch <- prometheus.MustNewConstMetric(
			c.connChildCnt,
			prometheus.GaugeValue,
			float64(len(conn.Children)),
			conn.Name,
		)

		// Child SA metrics
		for childName, child := range conn.Children {
			if child.RekeyTime > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.connChildRekeyTime,
					prometheus.GaugeValue,
					float64(child.RekeyTime),
					conn.Name, childName, child.Mode,
				)
			}

			if child.RekeyBytes > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.connChildRekeyBytes,
					prometheus.GaugeValue,
					float64(child.RekeyBytes),
					conn.Name, childName, child.Mode,
				)
			}

			if child.RekeyPackets > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.connChildRekeyPackets,
					prometheus.GaugeValue,
					float64(child.RekeyPackets),
					conn.Name, childName, child.Mode,
				)
			}
		}
	}
}

func (c *ConnsCollector) listConns() ([]Conn, error) {
	s, err := c.viciClientFn()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	req := vici.NewMessage()
	msgs, err := s.StreamedCommandRequest("list-conns", "list-conn", req)
	if err != nil {
		return nil, err
	}

	var conns []Conn
	for _, m := range msgs {
		if err = m.Err(); err != nil {
			log.Logger.Warnf("Message error: %v", err)
			return nil, err
		}

		// Extract connection name from the message
		// The message structure has the connection name as a key
		for _, key := range m.Keys() {
			connMsg := m.Get(key).(*vici.Message)

			var conn Conn
			if e := vici.UnmarshalMessage(connMsg, &conn); e != nil {
				log.Logger.Warnf("Message unmarshal error: %v", e)
				continue
			}
			conn.Name = key

			conns = append(conns, conn)
		}
	}

	return conns, nil
}
