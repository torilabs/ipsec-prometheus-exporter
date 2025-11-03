package strongswan

import (
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/strongswan/govici/vici"
)

func TestCertsCollector_Metrics(t *testing.T) {
	tests := []struct {
		name              string
		nowSeconds        int64
		viciClientErr     error
		msgsGetterFn      func() []*vici.Message
		viciSessionErr    error
		metricName        string
		wantMetricsHelp   string
		wantMetricsType   string
		wantMetricsLabels string
		wantMetricsValue  int
		wantMetricsCount  int
	}{
		{
			name:          "connection error",
			nowSeconds:    time.Now().Unix(),
			viciClientErr: errors.New("some error"),
			msgsGetterFn: func() []*vici.Message {
				return []*vici.Message{}
			},
			metricName:       "swtest_cert_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name:       "empty result",
			nowSeconds: time.Now().Unix(),
			msgsGetterFn: func() []*vici.Message {
				return []*vici.Message{}
			},
			metricName:       "swtest_cert_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name:       "error vici certMsgs",
			nowSeconds: time.Now().Unix(),
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				msg.Set("success", "no")
				msg.Set("errmsg", "some error")
				return []*vici.Message{msg}
			},
			metricName:       "swtest_cert_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name:       "one certificate",
			nowSeconds: time.Now().Unix(),
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				msg.Set("type", "X509")
				msg.Set("flags", "CA")
				msg.Set("data", loadCert("testdata/cert-ca.pem"))
				return []*vici.Message{msg}
			},
			metricName:       "swtest_cert_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 1,
			wantMetricsCount: 3,
		},
		{
			name:       "two certificates",
			nowSeconds: time.Now().Unix(),
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				msg.Set("type", "X509")
				msg.Set("flags", "CA")
				msg.Set("data", loadCert("testdata/cert-ca.pem"))
				msg2 := vici.NewMessage()
				msg2.Set("type", "X509")
				msg2.Set("flags", "CA")
				msg2.Set("data", loadCert("testdata/cert.pem"))
				return []*vici.Message{msg, msg2}
			},
			metricName:       "swtest_cert_count",
			wantMetricsHelp:  "Number of X509 certificates",
			wantMetricsType:  "gauge",
			wantMetricsValue: 2,
			wantMetricsCount: 5,
		},
		{
			name:       "valid certificate",
			nowSeconds: time.Now().Unix(),
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				msg.Set("type", "X509")
				msg.Set("flags", "CA")
				msg.Set("data", loadCert("testdata/cert-ca.pem"))
				return []*vici.Message{msg}
			},
			metricName:        "swtest_cert_valid",
			wantMetricsHelp:   "X509 certificate validity",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `not_after="2034-03-20T15:01:04Z",not_before="2024-03-20T15:01:04Z",serial_number="63:68:4d:00:11:20:7d:dc",subject="CN=Cyber Root CA,O=Cyber,C=CH"`,
			wantMetricsValue:  1,
			wantMetricsCount:  3,
		},
		{
			name:       "expired certificate",
			nowSeconds: time.Now().Unix(),
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				msg.Set("type", "X509")
				msg.Set("flags", "CA")
				msg.Set("data", loadCert("testdata/cert-expired.pem"))
				return []*vici.Message{msg}
			},
			metricName:        "swtest_cert_valid",
			wantMetricsHelp:   "X509 certificate validity",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `not_after="2025-10-22T18:59:10Z",not_before="2025-10-21T18:59:10Z",serial_number="d0:a9:1f:a5:00:4f:38:88",subject="CN=expired.example.local"`,
			wantMetricsValue:  0,
			wantMetricsCount:  3,
		},
		{
			name:       "certificate validity seconds",
			nowSeconds: 2026454400, // 2034-03-20T08:00:00Z
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				msg.Set("type", "X509")
				msg.Set("flags", "CA")
				msg.Set("data", loadCert("testdata/cert-ca.pem"))
				return []*vici.Message{msg}
			},
			metricName:        "swtest_cert_expire_secs",
			wantMetricsHelp:   "Seconds until the X509 certificate expires",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `not_after="2034-03-20T15:01:04Z",not_before="2024-03-20T15:01:04Z",serial_number="63:68:4d:00:11:20:7d:dc",subject="CN=Cyber Root CA,O=Cyber,C=CH"`,
			wantMetricsValue:  25264,
			wantMetricsCount:  3,
		},
		{
			name:       "certificate validity seconds (expired)",
			nowSeconds: 1761177600, // 2025-10-23T00:00:00Z
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				msg.Set("type", "X509")
				msg.Set("flags", "CA")
				msg.Set("data", loadCert("testdata/cert-expired.pem"))
				return []*vici.Message{msg}
			},
			metricName:        "swtest_cert_expire_secs",
			wantMetricsHelp:   "Seconds until the X509 certificate expires",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `not_after="2025-10-22T18:59:10Z",not_before="2025-10-21T18:59:10Z",serial_number="d0:a9:1f:a5:00:4f:38:88",subject="CN=expired.example.local"`,
			wantMetricsValue:  -18050,
			wantMetricsCount:  3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCertsCollector("swtest_",
				func() (ViciClient, error) {
					return &fakeViciClient{certMsgs: tt.msgsGetterFn(), err: tt.viciSessionErr}, tt.viciClientErr
				},
				func() time.Time {
					return time.Unix(tt.nowSeconds, 0)
				},
			)

			cnt := testutil.CollectAndCount(c)
			require.Equal(t, tt.wantMetricsCount, cnt, "metrics count")

			wantMetricsContent := fmt.Sprintf(`# HELP %s %s
# TYPE %s %s
%s{%s} %d
`, tt.metricName, tt.wantMetricsHelp, tt.metricName, tt.wantMetricsType, tt.metricName, tt.wantMetricsLabels, tt.wantMetricsValue)
			if err := testutil.CollectAndCompare(c, strings.NewReader(wantMetricsContent), tt.metricName); err != nil {
				t.Errorf("unexpected collecting result of '%s':\n%s", tt.metricName, err)
			}
		})
	}
}

func TestFormatSerialNumber(t *testing.T) {
	tests := []struct {
		name string
		sn   *big.Int
		want string
	}{
		{
			name: "Nil Serial Number",
			sn:   nil,
			want: "",
		},
		{
			name: "Zero Value",
			sn:   big.NewInt(0),
			want: "00",
		},
		{
			name: "Single Hex Digit Value",
			sn:   big.NewInt(10), // "0xa"
			want: "0a",
		},
		{
			name: "Odd Number of Hex Digits",
			sn:   big.NewInt(291), // "0x123"
			want: "01:23",
		},
		{
			name: "Even Number of Hex Digits",
			sn:   big.NewInt(48879), // "0xbeef"
			want: "be:ef",
		},
		{
			name: "Longer Even Hex String",
			sn:   big.NewInt(11259375), // "0xabcdef"
			want: "ab:cd:ef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, formatSerialNumber(tt.sn), "Serial Number format")
		})
	}
}

func loadCert(path string) string {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		panic("failed to parse PEM block")
	}
	return string(block.Bytes)
}
