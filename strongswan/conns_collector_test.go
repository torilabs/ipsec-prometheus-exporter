package strongswan

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/strongswan/govici/vici"
)

func TestConnsCollector_Metrics(t *testing.T) {
	tests := []struct {
		name              string
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
			viciClientErr: errors.New("some error"),
			msgsGetterFn: func() []*vici.Message {
				return []*vici.Message{}
			},
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of loaded connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name: "empty result",
			msgsGetterFn: func() []*vici.Message {
				return []*vici.Message{}
			},
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of loaded connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name: "error vici connMsgs",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				msg.Set("success", "no")
				msg.Set("errmsg", "some error")
				return []*vici.Message{msg}
			},
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of loaded connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name: "one connection",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg := vici.NewMessage()
				connMsg.Set("version", "IKEv2")
				connMsg.Set("reauth_time", "3600")
				connMsg.Set("rekey_time", "14400")
				msg.Set("test-conn", connMsg)
				return []*vici.Message{msg}
			},
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of loaded connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 1,
			wantMetricsCount: 5,
		},
		{
			name: "two connections",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg1 := vici.NewMessage()
				connMsg1.Set("version", "IKEv2")
				msg.Set("conn1", connMsg1)
				connMsg2 := vici.NewMessage()
				connMsg2.Set("version", "IKEv1")
				msg.Set("conn2", connMsg2)
				return []*vici.Message{msg}
			},
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of loaded connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 2,
			wantMetricsCount: 5,
		},
		{
			name: "connection version IKEv2",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg := vici.NewMessage()
				connMsg.Set("version", "IKEv2")
				msg.Set("test-conn", connMsg)
				return []*vici.Message{msg}
			},
			metricName:        "swtest_conn_version",
			wantMetricsHelp:   "IKE version for connection",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `conn_name="test-conn",version="IKEv2"`,
			wantMetricsValue:  1,
			wantMetricsCount:  3,
		},
		{
			name: "connection reauth time",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg := vici.NewMessage()
				connMsg.Set("version", "IKEv2")
				connMsg.Set("reauth_time", "3600")
				msg.Set("test-conn", connMsg)
				return []*vici.Message{msg}
			},
			metricName:        "swtest_conn_reauth_time",
			wantMetricsHelp:   "IKE_SA reauthentication interval in seconds",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `conn_name="test-conn"`,
			wantMetricsValue:  3600,
			wantMetricsCount:  4,
		},
		{
			name: "connection rekey time",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg := vici.NewMessage()
				connMsg.Set("version", "IKEv2")
				connMsg.Set("rekey_time", "14400")
				msg.Set("test-conn", connMsg)
				return []*vici.Message{msg}
			},
			metricName:        "swtest_conn_rekey_time",
			wantMetricsHelp:   "IKE_SA rekeying interval in seconds",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `conn_name="test-conn"`,
			wantMetricsValue:  14400,
			wantMetricsCount:  4,
		},
		{
			name: "connection with children",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg := vici.NewMessage()
				connMsg.Set("version", "IKEv2")
				childrenMsg := vici.NewMessage()
				childMsg := vici.NewMessage()
				childMsg.Set("mode", "tunnel")
				childMsg.Set("rekey_time", "3600")
				childrenMsg.Set("child1", childMsg)
				connMsg.Set("children", childrenMsg)
				msg.Set("test-conn", connMsg)
				return []*vici.Message{msg}
			},
			metricName:        "swtest_conn_child_count",
			wantMetricsHelp:   "Number of CHILD_SA configurations",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `conn_name="test-conn"`,
			wantMetricsValue:  1,
			wantMetricsCount:  4,
		},
		{
			name: "child rekey time",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg := vici.NewMessage()
				connMsg.Set("version", "IKEv2")
				childrenMsg := vici.NewMessage()
				childMsg := vici.NewMessage()
				childMsg.Set("mode", "tunnel")
				childMsg.Set("rekey_time", "3600")
				childrenMsg.Set("child1", childMsg)
				connMsg.Set("children", childrenMsg)
				msg.Set("test-conn", connMsg)
				return []*vici.Message{msg}
			},
			metricName:        "swtest_conn_child_rekey_time",
			wantMetricsHelp:   "CHILD_SA rekeying interval in seconds",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_name="child1",conn_name="test-conn",mode="tunnel"`,
			wantMetricsValue:  3600,
			wantMetricsCount:  4,
		},
		{
			name: "child rekey bytes",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg := vici.NewMessage()
				connMsg.Set("version", "IKEv2")
				childrenMsg := vici.NewMessage()
				childMsg := vici.NewMessage()
				childMsg.Set("mode", "tunnel")
				childMsg.Set("rekey_bytes", "1000000000")
				childrenMsg.Set("child1", childMsg)
				connMsg.Set("children", childrenMsg)
				msg.Set("test-conn", connMsg)
				return []*vici.Message{msg}
			},
			metricName:        "swtest_conn_child_rekey_bytes",
			wantMetricsHelp:   "CHILD_SA rekeying interval in bytes",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_name="child1",conn_name="test-conn",mode="tunnel"`,
			wantMetricsValue:  1000000000,
			wantMetricsCount:  4,
		},
		{
			name: "child rekey packets",
			msgsGetterFn: func() []*vici.Message {
				msg := vici.NewMessage()
				connMsg := vici.NewMessage()
				connMsg.Set("version", "IKEv2")
				childrenMsg := vici.NewMessage()
				childMsg := vici.NewMessage()
				childMsg.Set("mode", "tunnel")
				childMsg.Set("rekey_packets", "100000")
				childrenMsg.Set("child1", childMsg)
				connMsg.Set("children", childrenMsg)
				msg.Set("test-conn", connMsg)
				return []*vici.Message{msg}
			},
			metricName:        "swtest_conn_child_rekey_packets",
			wantMetricsHelp:   "CHILD_SA rekeying interval in packets",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_name="child1",conn_name="test-conn",mode="tunnel"`,
			wantMetricsValue:  100000,
			wantMetricsCount:  4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConnsCollector("swtest_",
				func() (ViciClient, error) {
					return &fakeViciClient{connMsgs: tt.msgsGetterFn(), err: tt.viciSessionErr}, tt.viciClientErr
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
