package strongswan

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/strongswan/govici/vici"
)

func TestCollector_Metrics(t *testing.T) {
	ikeMsg := vici.NewMessage()
	ikeMsg.Set("version", 5)
	ikeMsg.Set("uniqueid", "some-unique-id")
	msgs := vici.NewMessage()
	msgs.Set("ike-name", ikeMsg)
	wantIKEVersionMetricContent := `# HELP strongswan_ike_version Version of this IKE
# TYPE strongswan_ike_version gauge
strongswan_ike_version{ike_id="some-unique-id",ike_name="ike-name"} 5
`

	tests := []struct {
		name                       string
		certsEnabled               bool
		wantCertCountMetricContent string
	}{
		{
			name:         "cert metrics disabled",
			certsEnabled: false,
		},
		{
			name:         "cert metrics enabled",
			certsEnabled: true,
			wantCertCountMetricContent: `# HELP strongswan_cert_count Number of X509 certificates
# TYPE strongswan_cert_count gauge
strongswan_cert_count 0
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCollector(func() (ViciClient, error) {
				return &fakeViciClient{saMsgs: []*vici.Message{msgs}}, nil
			}, tt.certsEnabled)

			if err := testutil.CollectAndCompare(c, strings.NewReader(wantIKEVersionMetricContent), "strongswan_ike_version"); err != nil {
				t.Errorf("unexpected collecting result of 'swstrongswan_ike_version':\n%s", err)
			}

			if err := testutil.CollectAndCompare(c, strings.NewReader(tt.wantCertCountMetricContent), "strongswan_cert_count"); err != nil {
				t.Errorf("unexpected collecting result of 'swstrongswan_cert_count':\n%s", err)
			}
		})
	}
}
