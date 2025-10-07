package strongswan

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/strongswan/govici/vici"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
)

type ViciClient interface {
	StreamedCommandRequest(cmd string, event string, msg *vici.Message) ([]*vici.Message, error)
	Close() error
}

type viciClientFn func() (ViciClient, error)

type Collector struct {
	viciClientFn viciClientFn
	cs           []prometheus.Collector
}

func NewCollector(viciClientFn viciClientFn, certMetricsEnabled bool) *Collector {
	prefix := "strongswan_"
	cs := []prometheus.Collector{
		NewSasCollector(prefix, viciClientFn),
	}
	if certMetricsEnabled {
		log.Logger.Info("Certificate metrics enabled.")
		cs = append(cs, NewCertsCollector(prefix, viciClientFn, time.Now))
	}

	return &Collector{
		viciClientFn: viciClientFn,
		cs:           cs,
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, sc := range c.cs {
		sc.Describe(ch)
	}
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, sc := range c.cs {
		sc.Collect(ch)
	}
}
