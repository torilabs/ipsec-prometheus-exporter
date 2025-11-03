package strongswan

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/strongswan/govici/vici"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
)

type CertsCollector struct {
	viciClientFn viciClientFn
	now          func() time.Time

	certCnt        *prometheus.Desc
	certValid      *prometheus.Desc
	certExpireSecs *prometheus.Desc
}

const (
	typeX509Cert = "X509"
	keyType      = "type"
)

func NewCertsCollector(prefix string, viciClientFn viciClientFn, now func() time.Time) prometheus.Collector {
	return &CertsCollector{
		viciClientFn: viciClientFn,
		now:          now,

		certCnt: prometheus.NewDesc(
			prefix+"cert_count",
			"Number of X509 certificates",
			nil, nil,
		),
		certValid: prometheus.NewDesc(
			prefix+"cert_valid",
			"X509 certificate validity",
			[]string{"serial_number", "subject", "not_before", "not_after"}, nil,
		),
		certExpireSecs: prometheus.NewDesc(
			prefix+"cert_expire_secs",
			"Seconds until the X509 certificate expires",
			[]string{"serial_number", "subject", "not_before", "not_after"}, nil,
		),
	}
}

func (c *CertsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.certCnt
	ch <- c.certValid
	ch <- c.certExpireSecs
}

func (c *CertsCollector) Collect(ch chan<- prometheus.Metric) {
	certs, err := c.listCerts()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			c.certCnt,
			prometheus.GaugeValue,
			float64(0),
		)
		return
	}
	ch <- prometheus.MustNewConstMetric(
		c.certCnt,
		prometheus.GaugeValue,
		float64(len(certs)),
	)
	c.collectCertMetrics(certs, ch)
}

func (c *CertsCollector) collectCertMetrics(certs []Cert, ch chan<- prometheus.Metric) {
	now := c.now()
	for _, cert := range certs {
		if cert.Type != typeX509Cert {
			log.Logger.Warnf("Unknown certificate type: '%s'", cert.Type)
			continue
		}

		cert, err := x509.ParseCertificate([]byte(cert.Data))
		if err != nil {
			log.Logger.Warnf("Certificate parse error: %v", err)
			continue
		}

		valid := 0
		if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
			valid = 1
		}
		expireIn := cert.NotAfter.Sub(now).Seconds()

		labels := []string{
			formatSerialNumber(cert.SerialNumber),
			cert.Subject.String(),
			cert.NotBefore.Format(time.RFC3339),
			cert.NotAfter.Format(time.RFC3339),
		}
		ch <- prometheus.MustNewConstMetric(
			c.certValid,
			prometheus.GaugeValue,
			float64(valid),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.certExpireSecs,
			prometheus.GaugeValue,
			expireIn,
			labels...,
		)
	}
}

func (c *CertsCollector) listCerts() ([]Cert, error) {
	s, err := c.viciClientFn()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	req := vici.NewMessage()
	if err := req.Set(keyType, typeX509Cert); err != nil {
		return nil, err
	}

	msgs, err := s.StreamedCommandRequest("list-certs", "list-cert", req)
	if err != nil {
		return nil, err
	}

	var certs []Cert
	for _, m := range msgs {
		if err = m.Err(); err != nil {
			log.Logger.Warnf("Message error: %v", err)
			return nil, err
		}
		if m.Get(keyType) != typeX509Cert {
			log.Logger.Debugf("Unknown certificate type: '%s'", m.Get(keyType))
			continue
		}

		var cert Cert
		if e := vici.UnmarshalMessage(m, &cert); e != nil {
			log.Logger.Warnf("Message unmarshal error: %v", e)
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

func formatHexStrWithColons(hexStr string) string {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	var formatted strings.Builder
	for i, r := range hexStr {
		if i > 0 && i%2 == 0 {
			formatted.WriteRune(':')
		}

		formatted.WriteRune(r)
	}

	return formatted.String()
}

func formatSerialNumber(sn *big.Int) string {
	if sn == nil {
		return ""
	}

	hexStr := fmt.Sprintf("%x", sn)
	return formatHexStrWithColons(hexStr)
}
