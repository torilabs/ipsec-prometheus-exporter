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

type fakeViciClient struct {
	err            error
	saMsgs         []*vici.Message
	certMsgs       []*vici.Message
	closeTriggered int
}

func (fvc *fakeViciClient) StreamedCommandRequest(cmd string, event string, _ *vici.Message) ([]*vici.Message, error) {
	if cmd == "list-sas" && event == "list-sa" {
		return fvc.saMsgs, fvc.err
	}
	if cmd == "list-certs" && event == "list-cert" {
		return fvc.certMsgs, fvc.err
	}
	return nil, errors.New("invalid command")
}

func (fvc *fakeViciClient) Close() error {
	fvc.closeTriggered++
	return nil
}

func TestSasCollector_Metrics(t *testing.T) {
	tests := []struct {
		name              string
		viciClientErr     error
		msgsModifierFn    func(msgs *vici.Message)
		viciSessionErr    error
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
			metricName:       "swtest_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name:             "empty result",
			metricName:       "swtest_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name: "error vici saMsgs",
			msgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("success", "no")
				msgs.Set("errmsg", "some error")
			},
			metricName:       "swtest_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 0,
			wantMetricsCount: 1,
		},
		{
			name: "one ike count",
			msgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("ike-name", vici.NewMessage())
			},
			metricName:       "swtest_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 1,
			wantMetricsCount: 14,
		},
		{
			name: "two ike count",
			msgsModifierFn: func(msgs *vici.Message) {
				msgs.Set("ike-name1", vici.NewMessage())
				msgs.Set("ike-name2", vici.NewMessage())
			},
			metricName:       "swtest_ike_count",
			wantMetricsHelp:  "Number of known IKEs",
			wantMetricsType:  "gauge",
			wantMetricsValue: 2,
			wantMetricsCount: 27,
		},
		{
			name: "ike version & name & uniqueid",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("version", 5)
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_version",
			wantMetricsHelp:   "Version of this IKE",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  5,
			wantMetricsCount:  14,
		},
		{
			name: "ike status",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("state", "ESTABLISHED")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_status",
			wantMetricsHelp:   "Status of this IKE",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  14,
		},
		{
			name: "ike initiator",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("initiator", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_initiator",
			wantMetricsHelp:   "Flag if the server is the initiator for this connection",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  14,
		},
		{
			name: "ike NAT local",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("nat-local", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_nat_local",
			wantMetricsHelp:   "Flag if the local endpoint is behind nat",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  14,
		},
		{
			name: "ike NAT remote",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("nat-remote", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_nat_remote",
			wantMetricsHelp:   "Flag if the remote server is behind nat",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  14,
		},
		{
			name: "ike NAT fake",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("nat-fake", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_nat_fake",
			wantMetricsHelp:   "Flag if NAT situation has been faked as responder",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  14,
		},
		{
			name: "ike NAT any",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("nat-any", "yes")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_nat_any",
			wantMetricsHelp:   "Flag if any endpoint is behind a NAT (also if faked)",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
			wantMetricsCount:  14,
		},
		{
			name: "ike encryption key",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("encr-keysize", "1024")
				ikeMsg.Set("encr-alg", "SHA-256")
				ikeMsg.Set("dh-group", "DH")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_encryption_key_size",
			wantMetricsHelp:   "Key size of the encryption algorithm",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `algorithm="SHA-256",dh_group="DH",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1024,
			wantMetricsCount:  14,
		},
		{
			name: "ike integrity key",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("integ-keysize", "1024")
				ikeMsg.Set("integ-alg", "SHA-256")
				ikeMsg.Set("dh-group", "DH")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_integrity_key_size",
			wantMetricsHelp:   "Key size of the integrity algorithm",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `algorithm="SHA-256",dh_group="DH",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1024,
			wantMetricsCount:  14,
		},
		{
			name: "ike established",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("established", "565")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_established_seconds",
			wantMetricsHelp:   "Seconds since the IKE was established",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  565,
			wantMetricsCount:  14,
		},
		{
			name: "ike rekey",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("rekey-time", "12")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_rekey_seconds",
			wantMetricsHelp:   "Seconds until the IKE will be rekeyed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  12,
			wantMetricsCount:  14,
		},
		{
			name: "ike reauth",
			msgsModifierFn: func(msgs *vici.Message) {
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("reauth-time", "15")
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_reauth_seconds",
			wantMetricsHelp:   "Seconds until the IKE will be reauthed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  15,
			wantMetricsCount:  14,
		},
		{
			name: "ike children",
			msgsModifierFn: func(msgs *vici.Message) {
				childMsg1 := vici.NewMessage()
				childMsg1.Set("uniqueid", "child1-unique-id")
				childMsg2 := vici.NewMessage()
				childMsg2.Set("uniqueid", "child2-unique-id")
				msgsChildren := vici.NewMessage()
				msgsChildren.Set("child-1", childMsg1)
				msgsChildren.Set("child-2", childMsg2)
				ikeMsg := vici.NewMessage()
				ikeMsg.Set("child-sas", msgsChildren)
				ikeMsg.Set("uniqueid", "some-unique-id")
				msgs.Set("ike-name", ikeMsg)
			},
			metricName:        "swtest_ike_children_size",
			wantMetricsHelp:   "Count of children of this IKE",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  2,
			wantMetricsCount:  40,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := vici.NewMessage()
			if tt.msgsModifierFn != nil {
				tt.msgsModifierFn(msgs)
			}
			c := NewSasCollector("swtest_", func() (ViciClient, error) {
				return &fakeViciClient{saMsgs: []*vici.Message{msgs}, err: tt.viciSessionErr}, tt.viciClientErr
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

func TestSasCollector_MetricsChild(t *testing.T) {
	tests := []struct {
		name              string
		msgModifierFn     func(msg *vici.Message)
		metricName        string
		wantMetricsHelp   string
		wantMetricsType   string
		wantMetricsLabels string
		wantMetricsValue  int
	}{
		{
			name: "sa status",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("state", "INSTALLED")
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "swtest_sa_status",
			wantMetricsHelp:   "Status of this child sa",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  0,
		},
		{
			name: "sa encapsulation",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("encap", "yes")
			},
			metricName:        "swtest_sa_encap",
			wantMetricsHelp:   "Forced Encapsulation in UDP Packets",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1,
		},
		{
			name: "sa encryption key",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("encr-keysize", "1024")
				msg.Set("encr-alg", "SHA-256")
				msg.Set("dh-group", "DH")
			},
			metricName:        "swtest_sa_encryption_key_size",
			wantMetricsHelp:   "Key size of the encryption algorithm",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `algorithm="SHA-256",child_id="sa-unique-id",child_name="sa-name",dh_group="DH",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1024,
		},
		{
			name: "sa integrity key",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("integ-keysize", "1024")
				msg.Set("integ-alg", "SHA-256")
				msg.Set("dh-group", "DH")
			},
			metricName:        "swtest_sa_integrity_key_size",
			wantMetricsHelp:   "Key size of the integrity algorithm",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `algorithm="SHA-256",child_id="sa-unique-id",child_name="sa-name",dh_group="DH",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  1024,
		},
		{
			name: "sa bytes in",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("bytes-in", 125)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "swtest_sa_inbound_bytes",
			wantMetricsHelp:   "Number of input bytes processed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  125,
		},
		{
			name: "sa packets in",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("packets-in", 125)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "swtest_sa_inbound_packets",
			wantMetricsHelp:   "Number of input packets processed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  125,
		},
		{
			name: "sa last in seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("use-in", 60)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "swtest_sa_last_inbound_seconds",
			wantMetricsHelp:   "Number of seconds since the last inbound packet was received",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  60,
		},
		{
			name: "sa bytes out",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("bytes-out", 125)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "swtest_sa_outbound_bytes",
			wantMetricsHelp:   "Number of output bytes processed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  125,
		},
		{
			name: "sa packets out",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("packets-out", 125)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "swtest_sa_outbound_packets",
			wantMetricsHelp:   "Number of output packets processed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  125,
		},
		{
			name: "sa last out seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("use-out", 60)
				msg.Set("local-ts", []string{"local-ts-1", "local-ts-2"})
				msg.Set("remote-ts", []string{"remote-ts-1", "remote-ts-2"})
			},
			metricName:        "swtest_sa_last_outbound_seconds",
			wantMetricsHelp:   "Number of seconds since the last outbound packet was sent",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name",local_ts="local-ts-1;local-ts-2",remote_ts="remote-ts-1;remote-ts-2"`,
			wantMetricsValue:  60,
		},
		{
			name: "sa last established seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("install-time", 32)
			},
			metricName:        "swtest_sa_established_seconds",
			wantMetricsHelp:   "Seconds since the child SA was established",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  32,
		},
		{
			name: "sa last rekey seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("rekey-time", 33)
			},
			metricName:        "swtest_sa_rekey_seconds",
			wantMetricsHelp:   "Seconds until the child SA will be rekeyed",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  33,
		},
		{
			name: "sa lifetime seconds",
			msgModifierFn: func(msg *vici.Message) {
				msg.Set("life-time", 34)
			},
			metricName:        "swtest_sa_lifetime_seconds",
			wantMetricsHelp:   "Seconds until the lifetime expires",
			wantMetricsType:   "gauge",
			wantMetricsLabels: `child_id="sa-unique-id",child_name="sa-name",ike_id="some-unique-id",ike_name="ike-name"`,
			wantMetricsValue:  34,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saMsg := vici.NewMessage()
			saMsg.Set("name", "sa-name")
			saMsg.Set("uniqueid", "sa-unique-id")
			if tt.msgModifierFn != nil {
				tt.msgModifierFn(saMsg)
			}
			ikeMsg := vici.NewMessage()
			ikeMsg.Set("child-sas", map[string]any{"child-sa-name": saMsg})
			ikeMsg.Set("uniqueid", "some-unique-id")
			msgs := vici.NewMessage()
			msgs.Set("ike-name", ikeMsg)
			c := NewSasCollector("swtest_", func() (ViciClient, error) {
				return &fakeViciClient{saMsgs: []*vici.Message{msgs}}, nil
			})

			cnt := testutil.CollectAndCount(c)
			require.Equal(t, 27, cnt, "metrics count")

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
