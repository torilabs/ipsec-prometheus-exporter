package strongswan

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/strongswan/govici/vici"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
)

type ConnsCollector struct {
	viciClientFn viciClientFn

	connCnt             *prometheus.Desc
	connConfigured      *prometheus.Desc
	connChildConfigured *prometheus.Desc
}

func NewConnsCollector(prefix string, viciClientFn viciClientFn) prometheus.Collector {
	return &ConnsCollector{
		viciClientFn: viciClientFn,

		connCnt: prometheus.NewDesc(
			prefix+"conn_count",
			"Number of configured connections",
			nil, nil,
		),
		connConfigured: prometheus.NewDesc(
			prefix+"conn_configured",
			"Configured IKE connection (always 1 if configured)",
			[]string{"conn_name"}, nil,
		),
		connChildConfigured: prometheus.NewDesc(
			prefix+"conn_child_configured",
			"Configured child SA (always 1 if configured)",
			[]string{"conn_name", "child_name", "local_ts", "remote_ts"}, nil,
		),
	}
}

func (c *ConnsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.connCnt
	ch <- c.connConfigured
	ch <- c.connChildConfigured
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

	for connName, conn := range conns {
		ch <- prometheus.MustNewConstMetric(
			c.connConfigured,
			prometheus.GaugeValue,
			1,
			connName,
		)
		for childName, child := range conn.Children {
			localTSs := strings.Join(child.LocalTS, ";")
			remoteTSs := strings.Join(child.RemoteTS, ";")
			ch <- prometheus.MustNewConstMetric(
				c.connChildConfigured,
				prometheus.GaugeValue,
				1,
				connName, childName, localTSs, remoteTSs,
			)
		}
	}
}

func (c *ConnsCollector) listConns() (map[string]ConnConfig, error) {
	s, err := c.viciClientFn()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	msgs, err := s.StreamedCommandRequest("list-conns", "list-conn", nil)
	if err != nil {
		return nil, err
	}

	res := make(map[string]ConnConfig)
	for _, m := range msgs {
		if e := m.Err(); e != nil {
			log.Logger.Warnf("Message error: %v", e)
			continue
		}
		for _, k := range m.Keys() {
			rawMsg := m.Get(k).(*vici.Message)
			var conn ConnConfig
			if e := vici.UnmarshalMessage(rawMsg, &conn); e != nil {
				log.Logger.Warnf("Message unmarshal error: %v", e)
				continue
			}
			res[k] = conn
		}
	}
	return res, nil
}
