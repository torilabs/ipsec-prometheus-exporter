//go:build integration
// +build integration

package it_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/etherlabsio/healthcheck/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/suite"
	"github.com/strongswan/govici/vici"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
	"github.com/torilabs/ipsec-prometheus-exporter/strongswan"
)

type e2eTestSuite struct {
	suite.Suite
	port              int
	viciAddr          string
	viciNet           string
	ikeName           string
	enableCertMetrics bool
	enableConnMetrics bool
	stopServer        func()
}

func TestE2ETestSuite(t *testing.T) {
	suite.Run(t, &e2eTestSuite{
		port:              8079,
		viciAddr:          "10.2.0.3:4502",
		viciNet:           "tcp",
		ikeName:           "home",
		enableCertMetrics: true,
		enableConnMetrics: true,
	})
}

func (s *e2eTestSuite) SetupSuite() {
	// Setup logging
	if err := log.Setup("debug"); err != nil {
		s.Fail("failed to setup logging", err)
	}

	// Create vici client function
	viciClientFn := func() (strongswan.ViciClient, error) {
		sess, err := vici.NewSession(vici.WithAddr(s.viciNet, s.viciAddr))
		if err != nil {
			log.Logger.Warnf("Error connecting to Vici API: %s", err)
		}
		return sess, err
	}

	// Create collector with cert and conn metrics enabled
	cl := strongswan.NewCollector(viciClientFn, s.enableCertMetrics, s.enableConnMetrics)

	// Setup healthcheck
	checkers := make([]healthcheck.Option, 0)
	checkers = append(checkers, healthcheck.WithChecker("vici", cl))
	if err := prometheus.Register(cl); err != nil {
		s.Fail("failed to register prometheus collector", err)
	}

	// Start HTTP server
	s.stopServer = s.startServer(checkers)

	// Wait for server to be ready
	time.Sleep(2 * time.Second)
}

func (s *e2eTestSuite) TearDownSuite() {
	if s.stopServer != nil {
		s.stopServer()
	}
}

func (s *e2eTestSuite) startServer(checkers []healthcheck.Option) func() {
	mux := http.NewServeMux()
	mux.Handle("/healthcheck", http.TimeoutHandler(healthcheck.Handler(checkers...), 30*time.Second, "request timeout"))
	mux.Handle("/metrics", http.TimeoutHandler(promhttp.Handler(), 30*time.Second, "request timeout"))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		log.Logger.Infof("Starting test server on port %d", s.port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Logger.Errorf("Failed to start test server: %v", err)
		}
	}()

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Logger.Warnf("Error shutting down test server: %v", err)
		}
	}
}

func (s *e2eTestSuite) Test_EndToEnd_Healthcheck() {
	healthcheckBody := s.httpResponseBody("healthcheck")
	s.Contains(healthcheckBody, `"status":"OK"`)
}

func (s *e2eTestSuite) Test_EndToEnd_Metrics() {
	metricsBody := s.httpResponseBody("metrics")

	// Check for IKE count metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_count Number of known IKEs`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_count gauge`)
	s.Contains(metricsBody, `strongswan_ike_count 1`)

	// Check for IKE children size metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_children_size Count of children of this IKE`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_children_size gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_children_size{ike_id="1",ike_name="%s"} 1`, s.ikeName))

	// Check for IKE encryption metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_encryption_key_size Key size of the encryption algorithm`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_encryption_key_size gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_encryption_key_size{algorithm="AES_CBC",dh_group="CURVE_25519",ike_id="1",ike_name="%s"} 256`, s.ikeName))

	// Check for IKE established metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_established_seconds Seconds since the IKE was established`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_established_seconds gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_established_seconds{ike_id="1",ike_name="%s"}`, s.ikeName))

	// Check for IKE initiator metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_initiator Flag if the server is the initiator for this connection`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_initiator gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_initiator{ike_id="1",ike_name="%s"} 1`, s.ikeName))

	// Check for IKE integrity metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_integrity_key_size Key size of the integrity algorithm`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_integrity_key_size gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_integrity_key_size{algorithm="HMAC_SHA2_256_128",dh_group="CURVE_25519",ike_id="1",ike_name="%s"} 0`, s.ikeName))

	// Check for IKE NAT metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_nat_any Flag if any endpoint is behind a NAT (also if faked)`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_nat_any gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_nat_any{ike_id="1",ike_name="%s"} 0`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_ike_nat_fake Flag if NAT situation has been faked as responder`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_nat_fake gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_nat_fake{ike_id="1",ike_name="%s"} 0`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_ike_nat_local Flag if the local endpoint is behind nat`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_nat_local gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_nat_local{ike_id="1",ike_name="%s"} 0`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_ike_nat_remote Flag if the remote server is behind nat`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_nat_remote gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_nat_remote{ike_id="1",ike_name="%s"} 0`, s.ikeName))

	// Check for IKE reauth/rekey metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_reauth_seconds Seconds until the IKE will be reauthed`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_reauth_seconds gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_reauth_seconds{ike_id="1",ike_name="%s"} 0`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_ike_rekey_seconds Seconds until the IKE will be rekeyed`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_rekey_seconds gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_rekey_seconds{ike_id="1",ike_name="%s"}`, s.ikeName))

	// Check for IKE status and version metrics
	s.Contains(metricsBody, `# HELP strongswan_ike_status Status of this IKE`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_status gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_status{ike_id="1",ike_name="%s"} 1`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_ike_version Version of this IKE`)
	s.Contains(metricsBody, `# TYPE strongswan_ike_version gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_ike_version{ike_id="1",ike_name="%s"} 2`, s.ikeName))

	// Check for SA encap metrics
	s.Contains(metricsBody, `# HELP strongswan_sa_encap Forced Encapsulation in UDP Packets`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_encap gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_encap{child_id="1",child_name="net",ike_id="1",ike_name="%s"} 0`, s.ikeName))

	// Check for SA encryption metrics
	s.Contains(metricsBody, `# HELP strongswan_sa_encryption_key_size Key size of the encryption algorithm`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_encryption_key_size gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_encryption_key_size{algorithm="AES_GCM_16",child_id="1",child_name="net",dh_group="",ike_id="1",ike_name="%s"} 256`, s.ikeName))

	// Check for SA established metrics
	s.Contains(metricsBody, `# HELP strongswan_sa_established_seconds Seconds since the child SA was established`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_established_seconds gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_established_seconds{child_id="1",child_name="net",ike_id="1",ike_name="%s"}`, s.ikeName))

	// Check for SA traffic metrics
	s.Contains(metricsBody, `# HELP strongswan_sa_inbound_bytes Number of input bytes processed`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_inbound_bytes gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_inbound_bytes{child_id="1",child_name="net",ike_id="1",ike_name="%s",local_ts="10.3.0.1/32",remote_ts="10.2.0.0/24"} 0`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_sa_inbound_packets Number of input packets processed`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_inbound_packets gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_inbound_packets{child_id="1",child_name="net",ike_id="1",ike_name="%s",local_ts="10.3.0.1/32",remote_ts="10.2.0.0/24"} 0`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_sa_outbound_bytes Number of output bytes processed`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_outbound_bytes gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_outbound_bytes{child_id="1",child_name="net",ike_id="1",ike_name="%s",local_ts="10.3.0.1/32",remote_ts="10.2.0.0/24"} 0`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_sa_outbound_packets Number of output packets processed`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_outbound_packets gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_outbound_packets{child_id="1",child_name="net",ike_id="1",ike_name="%s",local_ts="10.3.0.1/32",remote_ts="10.2.0.0/24"} 0`, s.ikeName))

	// Check for SA integrity metrics
	s.Contains(metricsBody, `# HELP strongswan_sa_integrity_key_size Key size of the integrity algorithm`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_integrity_key_size gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_integrity_key_size{algorithm="",child_id="1",child_name="net",dh_group="",ike_id="1",ike_name="%s"} 0`, s.ikeName))

	// Check for SA last packet metrics
	s.Contains(metricsBody, `# HELP strongswan_sa_last_inbound_seconds Number of seconds since the last inbound packet was received`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_last_inbound_seconds gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_last_inbound_seconds{child_id="1",child_name="net",ike_id="1",ike_name="%s",local_ts="10.3.0.1/32",remote_ts="10.2.0.0/24"} 0`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_sa_last_outbound_seconds Number of seconds since the last outbound packet was sent`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_last_outbound_seconds gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_last_outbound_seconds{child_id="1",child_name="net",ike_id="1",ike_name="%s",local_ts="10.3.0.1/32",remote_ts="10.2.0.0/24"} 0`, s.ikeName))

	// Check for SA lifetime/rekey metrics
	s.Contains(metricsBody, `# HELP strongswan_sa_lifetime_seconds Seconds until the lifetime expires`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_lifetime_seconds gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_lifetime_seconds{child_id="1",child_name="net",ike_id="1",ike_name="%s"}`, s.ikeName))

	s.Contains(metricsBody, `# HELP strongswan_sa_rekey_seconds Seconds until the child SA will be rekeyed`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_rekey_seconds gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_rekey_seconds{child_id="1",child_name="net",ike_id="1",ike_name="%s"}`, s.ikeName))

	// Check for SA status metrics
	s.Contains(metricsBody, `# HELP strongswan_sa_status Status of this child sa`)
	s.Contains(metricsBody, `# TYPE strongswan_sa_status gauge`)
	s.Contains(metricsBody, fmt.Sprintf(`strongswan_sa_status{child_id="1",child_name="net",ike_id="1",ike_name="%s",local_ts="10.3.0.1/32",remote_ts="10.2.0.0/24"} 0`, s.ikeName))
}

func (s *e2eTestSuite) Test_EndToEnd_CertMetrics() {
	metricsBody := s.httpResponseBody("metrics")

	// Check for certificate count metric
	s.Contains(metricsBody, `# HELP strongswan_cert_count Number of X509 certificates`)
	s.Contains(metricsBody, `# TYPE strongswan_cert_count gauge`)
	s.Contains(metricsBody, `strongswan_cert_count 3`)

	// Check for certificate expiration metrics
	s.Contains(metricsBody, `# HELP strongswan_cert_expire_secs Seconds until the X509 certificate expires`)
	s.Contains(metricsBody, `# TYPE strongswan_cert_expire_secs gauge`)

	// Check client certificate
	s.Contains(metricsBody, `strongswan_cert_expire_secs{not_after="2028-03-20T15:01:04Z",not_before="2024-03-20T15:01:04Z",serial_number="08:c7:34:ec:6d:c0:cd:49",subject="CN=client.strongswan.org,O=Cyber,C=CH"}`)

	// Check server certificate
	s.Contains(metricsBody, `strongswan_cert_expire_secs{not_after="2028-03-20T15:01:04Z",not_before="2024-03-20T15:01:04Z",serial_number="76:38:40:b8:25:18:44:0a",subject="CN=server.strongswan.org,O=Cyber,C=CH"}`)

	// Check CA certificate
	s.Contains(metricsBody, `strongswan_cert_expire_secs{not_after="2034-03-20T15:01:04Z",not_before="2024-03-20T15:01:04Z",serial_number="63:68:4d:00:11:20:7d:dc",subject="CN=Cyber Root CA,O=Cyber,C=CH"}`)

	// Check for certificate validity metrics
	s.Contains(metricsBody, `# HELP strongswan_cert_valid X509 certificate validity`)
	s.Contains(metricsBody, `# TYPE strongswan_cert_valid gauge`)

	// Check client certificate validity
	s.Contains(metricsBody, `strongswan_cert_valid{not_after="2028-03-20T15:01:04Z",not_before="2024-03-20T15:01:04Z",serial_number="08:c7:34:ec:6d:c0:cd:49",subject="CN=client.strongswan.org,O=Cyber,C=CH"} 1`)

	// Check server certificate validity
	s.Contains(metricsBody, `strongswan_cert_valid{not_after="2028-03-20T15:01:04Z",not_before="2024-03-20T15:01:04Z",serial_number="76:38:40:b8:25:18:44:0a",subject="CN=server.strongswan.org,O=Cyber,C=CH"} 1`)

	// Check CA certificate validity
	s.Contains(metricsBody, `strongswan_cert_valid{not_after="2034-03-20T15:01:04Z",not_before="2024-03-20T15:01:04Z",serial_number="63:68:4d:00:11:20:7d:dc",subject="CN=Cyber Root CA,O=Cyber,C=CH"} 1`)
}

func (s *e2eTestSuite) Test_EndToEnd_ConnMetrics() {
	metricsBody := s.httpResponseBody("metrics")

	// Check for connection count metric
	s.Contains(metricsBody, `# HELP strongswan_conn_count Number of loaded connections`)
	s.Contains(metricsBody, `# TYPE strongswan_conn_count gauge`)
	s.Contains(metricsBody, `strongswan_conn_count 4`)

	// Check for connection version metric
	s.Contains(metricsBody, `# HELP strongswan_conn_version IKE version for connection`)
	s.Contains(metricsBody, `# TYPE strongswan_conn_version gauge`)
	s.Contains(metricsBody, `strongswan_conn_version{conn_name="home",version="IKEv2"} 1`)

	// Check for connection rekey time metric
	s.Contains(metricsBody, `# HELP strongswan_conn_rekey_time IKE_SA rekeying interval in seconds`)
	s.Contains(metricsBody, `# TYPE strongswan_conn_rekey_time gauge`)
	s.Contains(metricsBody, `strongswan_conn_rekey_time{conn_name="home"} 14400`)

	// Check for child count metric
	s.Contains(metricsBody, `# HELP strongswan_conn_child_count Number of CHILD_SA configurations`)
	s.Contains(metricsBody, `# TYPE strongswan_conn_child_count gauge`)
	s.Contains(metricsBody, `strongswan_conn_child_count{conn_name="eap"} 1`)
	s.Contains(metricsBody, `strongswan_conn_child_count{conn_name="home"} 2`)

	// Check for child rekey time metric
	s.Contains(metricsBody, `# HELP strongswan_conn_child_rekey_time CHILD_SA rekeying interval in seconds`)
	s.Contains(metricsBody, `# TYPE strongswan_conn_child_rekey_time gauge`)
	s.Contains(metricsBody, `strongswan_conn_child_rekey_time{child_name="net",conn_name="home",mode="TUNNEL"} 3600`)
}

func (s *e2eTestSuite) httpResponseBody(path string) string {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d/%s", s.port, path), nil)
	s.NoError(err)

	client := http.Client{
		Timeout: 10 * time.Second,
	}
	response, err := client.Do(req)
	s.NoError(err)
	defer response.Body.Close()

	s.Equal(http.StatusOK, response.StatusCode)

	byteBody, err := io.ReadAll(response.Body)
	s.NoError(err)

	return strings.TrimSpace(string(byteBody))
}
