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
		msgsModifierFn    func(msgs *vici.Message)
		metricName        string
		wantMetricsHelp   string
		wantMetricsType   string
		wantMetricsLabels string
		wantMetricsValue  int
		wantMetricsCount  int
	}{
		{
			name:             "connection error",
			viciClientErr:    errors.New("some error"),
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of configured connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name:             "empty result",
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of configured connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name: "error vici messages",
			msgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("success", "no")
				msgs.Set("errmsg", "some error")
			},
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of configured connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name: "one connection count",
			msgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("conn-1", vici.NewMessage())
			},
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of configured connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 1,
			wantMetricsCount: 2,
		},
		{
			name: "two connections count",
			msgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("conn-1", vici.NewMessage())
				msgs.Set("conn-2", vici.NewMessage())
			},
			metricName:       "swtest_conn_count",
			wantMetricsHelp:  "Number of configured connections",
			wantMetricsType:  "gauge",
			wantMetricsValue: 2,
			wantMetricsCount: 3,
		},
		{
			name: "conn configured",
			msgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("my-conn", vici.NewMessage())
			},
			metricName:        "swtest_conn_configured",
			wantMetricsHelp:   "Configured IKE connection (always 1 if configured)",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `conn_name="my-conn"`,
			wantMetricsValue:  1,
			wantMetricsCount:  2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := vici.NewMessage()
			if tt.msgsModifierFn != nil {
				tt.msgsModifierFn(msgs)
			}
			c := NewConnsCollector("swtest_", func() (ViciClient, error) {
				return &fakeViciClient{connMsgs: []*vici.Message{msgs}}, tt.viciClientErr
			})

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

func TestConnsCollector_MetricsChild(t *testing.T) {
	tests := []struct {
		name              string
		childModifierFn   func(msg *vici.Message)
		metricName        string
		wantMetricsHelp   string
		wantMetricsType   string
		wantMetricsLabels string
		wantMetricsValue  int
	}{
		{
			name: "child configured with traffic selectors",
			childModifierFn: func(msg *vici.Message) {
				msg.Set("local-ts", []string{"10.0.0.0/24"})
				msg.Set("remote-ts", []string{"192.168.1.0/24"})
			},
			metricName:        "swtest_conn_child_configured",
			wantMetricsHelp:   "Configured child SA (always 1 if configured)",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_name="child-1",conn_name="my-conn",local_ts="10.0.0.0/24",remote_ts="192.168.1.0/24"`,
			wantMetricsValue:  1,
		},
		{
			name: "child configured with multiple traffic selectors",
			childModifierFn: func(msg *vici.Message) {
				msg.Set("local-ts", []string{"10.0.0.0/24", "10.0.1.0/24"})
				msg.Set("remote-ts", []string{"192.168.1.0/24", "192.168.2.0/24"})
			},
			metricName:        "swtest_conn_child_configured",
			wantMetricsHelp:   "Configured child SA (always 1 if configured)",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_name="child-1",conn_name="my-conn",local_ts="10.0.0.0/24;10.0.1.0/24",remote_ts="192.168.1.0/24;192.168.2.0/24"`,
			wantMetricsValue:  1,
		},
		{
			name:              "child configured without traffic selectors",
			childModifierFn:   func(msg *vici.Message) {},
			metricName:        "swtest_conn_child_configured",
			wantMetricsHelp:   "Configured child SA (always 1 if configured)",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_name="child-1",conn_name="my-conn",local_ts="",remote_ts=""`,
			wantMetricsValue:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childMsg := vici.NewMessage()
			if tt.childModifierFn != nil {
				tt.childModifierFn(childMsg)
			}
			childrenMsg := vici.NewMessage()
			childrenMsg.Set("child-1", childMsg)
			connMsg := vici.NewMessage()
			connMsg.Set("children", childrenMsg)
			msgs := vici.NewMessage()
			msgs.Set("my-conn", connMsg)

			c := NewConnsCollector("swtest_", func() (ViciClient, error) {
				return &fakeViciClient{connMsgs: []*vici.Message{msgs}}, nil
			})

			cnt := testutil.CollectAndCount(c)
			require.Equal(t, 3, cnt, "metrics count")

			wantMetricsContent := fmt.Sprintf(`# HELP %s %s
# TYPE %s %s
%s{%s} %d
`, tt.metricName, tt.wantMetricsHelp, tt.metricName, tt.wantMetricsType, tt.metricName, tt.wantMetricsLabels, tt.wantMetricsValue)
			if err := testutil.CollectAndCompare(c, strings.NewReader(wantMetricsContent), tt.metricName); err != nil {
				t.Errorf("unexpected collecting result of child '%s':\n%s", tt.metricName, err)
			}
		})
	}
}
