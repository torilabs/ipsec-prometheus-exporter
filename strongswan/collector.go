package strongswan

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/strongswan/govici/vici"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
)

type connectionStatus int

const (
	tunnelInstalled       connectionStatus = 0
	connectionEstablished connectionStatus = 1
	down                  connectionStatus = 2
	unknown               connectionStatus = 3
)

type ViciClient interface {
	StreamedCommandRequest(cmd string, event string, msg *vici.Message) ([]*vici.Message, error)
	Close() error
}

type viciClientFn func() (ViciClient, error)

type Collector struct {
	viciClientFn viciClientFn

	up               *prometheus.Desc
	ikeCnt           *prometheus.Desc
	ikeVersion       *prometheus.Desc
	ikeStatus        *prometheus.Desc
	ikeInitiator     *prometheus.Desc
	ikeNatLocal      *prometheus.Desc
	ikeNatRemote     *prometheus.Desc
	ikeNatFake       *prometheus.Desc
	ikeNatAny        *prometheus.Desc
	ikeEncKeySize    *prometheus.Desc
	ikeIntegKeySize  *prometheus.Desc
	ikeEstablishSecs *prometheus.Desc
	ikeRekeySecs     *prometheus.Desc
	ikeReauthSecs    *prometheus.Desc
	ikeChildren      *prometheus.Desc

	saStatus        *prometheus.Desc
	saEncap         *prometheus.Desc
	saEncKeySize    *prometheus.Desc
	saIntegKeySize  *prometheus.Desc
	saBytesIn       *prometheus.Desc
	saPacketsIn     *prometheus.Desc
	saLastInSecs    *prometheus.Desc
	saBytesOut      *prometheus.Desc
	saPacketsOut    *prometheus.Desc
	saLastOutSecs   *prometheus.Desc
	saEstablishSecs *prometheus.Desc
	saRekeySecs     *prometheus.Desc
	saLifetimeSecs  *prometheus.Desc
}

func NewCollector(viciClientFn viciClientFn) *Collector {
	prefix := "strongswan_"
	return &Collector{
		viciClientFn: viciClientFn,

		up: prometheus.NewDesc(
			prefix+"up",
			"Whether scraping metrics was successful.",
			nil, nil,
		),
		ikeCnt: prometheus.NewDesc(
			prefix+"ike_count",
			"Number of known IKEs",
			nil, nil,
		),
		ikeVersion: prometheus.NewDesc(
			prefix+"ike_version",
			"Version of this IKE",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeStatus: prometheus.NewDesc(
			prefix+"ike_status",
			"Status of this IKE",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeInitiator: prometheus.NewDesc(
			prefix+"ike_initiator",
			"Flag if the server is the initiator for this connection",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeNatLocal: prometheus.NewDesc(
			prefix+"ike_nat_local",
			"Flag if the local endpoint is behind nat",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeNatRemote: prometheus.NewDesc(
			prefix+"ike_nat_remote",
			"Flag if the remote server is behind nat",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeNatFake: prometheus.NewDesc(
			prefix+"ike_nat_fake",
			"Flag if NAT situation has been faked as responder",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeNatAny: prometheus.NewDesc(
			prefix+"ike_nat_any",
			"Flag if any endpoint is behind a NAT (also if faked)",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeEncKeySize: prometheus.NewDesc(
			prefix+"ike_encryption_key_size",
			"Key size of the encryption algorithm",
			[]string{"ike_name", "ike_id", "algorithm", "dh_group"}, nil,
		),
		ikeIntegKeySize: prometheus.NewDesc(
			prefix+"ike_integrity_key_size",
			"Key size of the integrity algorithm",
			[]string{"ike_name", "ike_id", "algorithm", "dh_group"}, nil,
		),
		ikeEstablishSecs: prometheus.NewDesc(
			prefix+"ike_established_seconds",
			"Seconds since the IKE was established",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeRekeySecs: prometheus.NewDesc(
			prefix+"ike_rekey_seconds",
			"Seconds until the IKE will be rekeyed",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeReauthSecs: prometheus.NewDesc(
			prefix+"ike_reauth_seconds",
			"Seconds until the IKE will be reauthed",
			[]string{"ike_name", "ike_id"}, nil,
		),
		ikeChildren: prometheus.NewDesc(
			prefix+"ike_children_size",
			"Count of children of this IKE",
			[]string{"ike_name", "ike_id"}, nil,
		),

		saStatus: prometheus.NewDesc(
			prefix+"sa_status",
			"Status of this child sa",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "local_ts", "remote_ts"}, nil,
		),
		saEncap: prometheus.NewDesc(
			prefix+"sa_encap",
			"Forced Encapsulation in UDP Packets",
			[]string{"ike_name", "ike_id", "child_name", "child_id"}, nil,
		),
		saEncKeySize: prometheus.NewDesc(
			prefix+"sa_encryption_key_size",
			"Key size of the encryption algorithm",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "algorithm", "dh_group"}, nil,
		),
		saIntegKeySize: prometheus.NewDesc(
			prefix+"sa_integrity_key_size",
			"Key size of the integrity algorithm",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "algorithm", "dh_group"}, nil,
		),
		saBytesIn: prometheus.NewDesc(
			prefix+"sa_inbound_bytes",
			"Number of input bytes processed",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "local_ts", "remote_ts"}, nil,
		),
		saPacketsIn: prometheus.NewDesc(
			prefix+"sa_inbound_packets",
			"Number of input packets processed",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "local_ts", "remote_ts"}, nil,
		),
		saLastInSecs: prometheus.NewDesc(
			prefix+"sa_last_inbound_seconds",
			"Number of seconds since the last inbound packet was received",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "local_ts", "remote_ts"}, nil,
		),
		saBytesOut: prometheus.NewDesc(
			prefix+"sa_outbound_bytes",
			"Number of output bytes processed",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "local_ts", "remote_ts"}, nil,
		),
		saPacketsOut: prometheus.NewDesc(
			prefix+"sa_outbound_packets",
			"Number of output packets processed",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "local_ts", "remote_ts"}, nil,
		),
		saLastOutSecs: prometheus.NewDesc(
			prefix+"sa_last_outbound_seconds",
			"Number of seconds since the last outbound packet was sent",
			[]string{"ike_name", "ike_id", "child_name", "child_id", "local_ts", "remote_ts"}, nil,
		),
		saEstablishSecs: prometheus.NewDesc(
			prefix+"sa_established_seconds",
			"Seconds since the child SA was established",
			[]string{"ike_name", "ike_id", "child_name", "child_id"}, nil,
		),
		saRekeySecs: prometheus.NewDesc(
			prefix+"sa_rekey_seconds",
			"Seconds until the child SA will be rekeyed",
			[]string{"ike_name", "ike_id", "child_name", "child_id"}, nil,
		),
		saLifetimeSecs: prometheus.NewDesc(
			prefix+"sa_lifetime_seconds",
			"Seconds until the lifetime expires",
			[]string{"ike_name", "ike_id", "child_name", "child_id"}, nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.ikeCnt
	ch <- c.ikeVersion
	ch <- c.ikeStatus
	ch <- c.ikeInitiator
	ch <- c.ikeNatLocal
	ch <- c.ikeNatRemote
	ch <- c.ikeNatFake
	ch <- c.ikeNatAny
	ch <- c.ikeEncKeySize
	ch <- c.ikeIntegKeySize
	ch <- c.ikeEstablishSecs
	ch <- c.ikeRekeySecs
	ch <- c.ikeReauthSecs
	ch <- c.ikeChildren

	ch <- c.saStatus
	ch <- c.saEncap
	ch <- c.saEncKeySize
	ch <- c.saIntegKeySize
	ch <- c.saBytesIn
	ch <- c.saPacketsIn
	ch <- c.saLastInSecs
	ch <- c.saBytesOut
	ch <- c.saPacketsOut
	ch <- c.saLastOutSecs
	ch <- c.saEstablishSecs
	ch <- c.saRekeySecs
	ch <- c.saLifetimeSecs
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	sas, err := c.listSas()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			c.ikeCnt,
			prometheus.GaugeValue,
			float64(0),
		)
		ch <- prometheus.MustNewConstMetric(
			c.up,
			prometheus.GaugeValue,
			float64(0),
		)
		return
	}
	ch <- prometheus.MustNewConstMetric(
		c.ikeCnt,
		prometheus.GaugeValue,
		float64(len(sas)),
	)
	ch <- prometheus.MustNewConstMetric(
		c.up,
		prometheus.GaugeValue,
		float64(1),
	)
	for _, ikeSa := range sas {
		c.collectIkeMetrics(ikeSa, ch)
		for _, child := range ikeSa.Children {
			c.collectIkeChildMetrics(ikeSa.Name, ikeSa.UniqueID, child, ch)
		}
	}
}

func (c *Collector) collectIkeMetrics(ikeSa IkeSa, ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		c.ikeVersion,
		prometheus.GaugeValue,
		float64(ikeSa.Version),
		ikeSa.Name, ikeSa.UniqueID,
	)

	ch <- prometheus.MustNewConstMetric(
		c.ikeStatus,
		prometheus.GaugeValue,
		float64(viciStateToInt(ikeSa.State)),
		ikeSa.Name, ikeSa.UniqueID,
	)

	ch <- prometheus.MustNewConstMetric(
		c.ikeInitiator,
		prometheus.GaugeValue,
		float64(viciBoolToInt(ikeSa.Initiator)),
		ikeSa.Name, ikeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeNatLocal,
		prometheus.GaugeValue,
		float64(viciBoolToInt(ikeSa.NatLocal)),
		ikeSa.Name, ikeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeNatRemote,
		prometheus.GaugeValue,
		float64(viciBoolToInt(ikeSa.NatRemote)),
		ikeSa.Name, ikeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeNatFake,
		prometheus.GaugeValue,
		float64(viciBoolToInt(ikeSa.NatFake)),
		ikeSa.Name, ikeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeNatAny,
		prometheus.GaugeValue,
		float64(viciBoolToInt(ikeSa.NatAny)),
		ikeSa.Name, ikeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeEncKeySize,
		prometheus.GaugeValue,
		float64(ikeSa.EncKey),
		ikeSa.Name, ikeSa.UniqueID, ikeSa.EncAlg, ikeSa.DHGroup,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeIntegKeySize,
		prometheus.GaugeValue,
		float64(ikeSa.IntegKey),
		ikeSa.Name, ikeSa.UniqueID, ikeSa.IntegAlg, ikeSa.DHGroup,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeEstablishSecs,
		prometheus.GaugeValue,
		float64(ikeSa.EstablishSec),
		ikeSa.Name, ikeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeRekeySecs,
		prometheus.GaugeValue,
		float64(ikeSa.RekeySec),
		ikeSa.Name, ikeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeReauthSecs,
		prometheus.GaugeValue,
		float64(ikeSa.ReauthSec),
		ikeSa.Name, ikeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ikeChildren,
		prometheus.GaugeValue,
		float64(len(ikeSa.Children)),
		ikeSa.Name, ikeSa.UniqueID,
	)
}

func (c *Collector) collectIkeChildMetrics(name string, uniqueID string, childIkeSa ChildIkeSa, ch chan<- prometheus.Metric) {
	localTSs := strings.Join(childIkeSa.LocalTS, ";")
	remoteTSs := strings.Join(childIkeSa.RemoteTS, ";")
	ch <- prometheus.MustNewConstMetric(
		c.saStatus,
		prometheus.GaugeValue,
		float64(viciStateToInt(childIkeSa.State)),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, localTSs, remoteTSs,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saEncap,
		prometheus.GaugeValue,
		float64(viciBoolToInt(childIkeSa.Encap)),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saEncKeySize,
		prometheus.GaugeValue,
		float64(childIkeSa.EncKey),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, childIkeSa.EncAlg, childIkeSa.DHGroup,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saIntegKeySize,
		prometheus.GaugeValue,
		float64(childIkeSa.IntegKey),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, childIkeSa.IntegAlg, childIkeSa.DHGroup,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saBytesIn,
		prometheus.GaugeValue,
		float64(childIkeSa.BytesIn),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, localTSs, remoteTSs,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saPacketsIn,
		prometheus.GaugeValue,
		float64(childIkeSa.PacketsIn),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, localTSs, remoteTSs,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saLastInSecs,
		prometheus.GaugeValue,
		float64(childIkeSa.LastInSec),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, localTSs, remoteTSs,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saBytesOut,
		prometheus.GaugeValue,
		float64(childIkeSa.BytesOut),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, localTSs, remoteTSs,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saPacketsOut,
		prometheus.GaugeValue,
		float64(childIkeSa.PacketsOut),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, localTSs, remoteTSs,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saLastOutSecs,
		prometheus.GaugeValue,
		float64(childIkeSa.LastOutSec),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID, localTSs, remoteTSs,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saEstablishSecs,
		prometheus.GaugeValue,
		float64(childIkeSa.EstablishSec),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saRekeySecs,
		prometheus.GaugeValue,
		float64(childIkeSa.RekeySec),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID,
	)
	ch <- prometheus.MustNewConstMetric(
		c.saLifetimeSecs,
		prometheus.GaugeValue,
		float64(childIkeSa.LifetimeSec),
		name, uniqueID, childIkeSa.Name, childIkeSa.UniqueID,
	)
}

func (c *Collector) listSas() ([]IkeSa, error) {
	s, err := c.viciClientFn()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	var res []IkeSa
	msgs, err := s.StreamedCommandRequest("list-sas", "list-sa", nil)
	if err != nil {
		return res, err
	}
	for _, m := range msgs {
		if e := m.Err(); e != nil {
			log.Logger.Warnf("Message error: %v", e)
			continue
		}
		for _, k := range m.Keys() {
			rawMsg := m.Get(k).(*vici.Message)
			var ikeSa IkeSa
			if e := vici.UnmarshalMessage(rawMsg, &ikeSa); e != nil {
				log.Logger.Warnf("Message unmarshal error: %v", e)
				continue
			}
			ikeSa.Name = k
			res = append(res, ikeSa)
		}
	}
	return res, nil
}

func viciBoolToInt(v string) int {
	if v == "yes" {
		return 1
	}
	return 0
}

func viciStateToInt(v string) connectionStatus {
	switch v {
	case "ESTABLISHED":
		return connectionEstablished
	case "INSTALLED":
		return tunnelInstalled
	case "REKEYED":
		return tunnelInstalled
	case "REKEYING":
		return tunnelInstalled
	case "":
		return down
	default:
		return unknown
	}
}
