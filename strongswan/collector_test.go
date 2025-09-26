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

	c := NewCollector(func() (ViciClient, error) {
		return &fakeViciClient{msgs: []*vici.Message{msgs}}, nil
	})

	wantMetricsContent := `# HELP strongswan_ike_version Version of this IKE
# TYPE strongswan_ike_version gauge
strongswan_ike_version{ike_id="some-unique-id",ike_name="ike-name"} 5
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(wantMetricsContent), "strongswan_ike_version"); err != nil {
		t.Errorf("unexpected collecting result of 'swstrongswan_ike_version':\n%s", err)
	}
}
