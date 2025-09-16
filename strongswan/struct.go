package strongswan

/*
IkeSa documentation: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-sa
*/
type IkeSa struct {
	Name         string
	UniqueID     string                `vici:"uniqueid"`
	Version      int                   `vici:"version"`
	State        string                `vici:"state"`
	LocalHost    string                `vici:"local-host"`
	LocalPort    int                   `vici:"local-port"`
	LocalID      string                `vici:"local-id"`
	RemoteHost   string                `vici:"remote-host"`
	RemotePort   int                   `vici:"remote-port"`
	RemoteID     string                `vici:"remote-id"`
	Initiator    string                `vici:"initiator"`
	InitiatorSpi string                `vici:"initiator-spi"`
	ResponderSpi string                `vici:"responder-spi"`
	NatLocal     string                `vici:"nat-local"`
	NatRemote    string                `vici:"nat-remote"`
	NatFake      string                `vici:"nat-fake"`
	NatAny       string                `vici:"nat-any"`
	EncAlg       string                `vici:"encr-alg"`
	EncKey       int                   `vici:"encr-keysize"`
	IntegAlg     string                `vici:"integ-alg"`
	IntegKey     int                   `vici:"integ-keysize"`
	PrfAlg       string                `vici:"prf-alg"`
	DHGroup      string                `vici:"dh-group"`
	EstablishSec int64                 `vici:"established"`
	RekeySec     int64                 `vici:"rekey-time"`
	ReauthSec    int64                 `vici:"reauth-time"`
	Children     map[string]ChildIkeSa `vici:"child-sas"`
}

type ChildIkeSa struct {
	Name         string   `vici:"name"`
	UniqueID     string   `vici:"uniqueid"`
	ReqID        string   `vici:"reqid"`
	State        string   `vici:"state"`
	Mode         string   `vici:"mode"`
	Protocol     string   `vici:"protocol"`
	Encap        string   `vici:"encap"`
	EncAlg       string   `vici:"encr-alg"`
	EncKey       int      `vici:"encr-keysize"`
	IntegAlg     string   `vici:"integ-alg"`
	IntegKey     int      `vici:"integ-keysize"`
	PrfAlg       string   `vici:"prf-alg"`
	DHGroup      string   `vici:"dh-group"`
	Esn          string   `vici:"esn"`
	BytesIn      int64    `vici:"bytes-in"`
	PacketsIn    int64    `vici:"packets-in"`
	LastInSec    int64    `vici:"use-in"`
	BytesOut     int64    `vici:"bytes-out"`
	PacketsOut   int64    `vici:"packets-out"`
	LastOutSec   int64    `vici:"use-out"`
	RekeySec     int64    `vici:"rekey-time"`
	LifetimeSec  int64    `vici:"life-time"`
	EstablishSec int64    `vici:"install-time"`
	LocalTS      []string `vici:"local-ts"`
	RemoteTS     []string `vici:"remote-ts"`
}

/*
Certs documentation: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md#list-cert
*/
type Crt struct {
	Type  string `vici:"type"`
	Flags string `vici:"flags"`
	Data  string `vici:"data"`
}
