package strongswan

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/strongswan/govici/vici"
)

type ViciClient interface {
	StreamedCommandRequest(cmd string, event string, msg *vici.Message) ([]*vici.Message, error)
	Close() error
}

type viciClientFn func() (ViciClient, error)

type Collector struct {
	viciClientFn viciClientFn
	sasCollector prometheus.Collector
}

func NewCollector(viciClientFn viciClientFn) *Collector {
	prefix := "strongswan_"
	return &Collector{
		viciClientFn: viciClientFn,
		sasCollector: NewSasCollector(prefix, viciClientFn),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.sasCollector.Describe(ch)
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.sasCollector.Collect(ch)
}
