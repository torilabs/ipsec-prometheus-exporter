package config

import (
	"io/fs"
	"os"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		rawCfg  string
		wantCfg Configuration
		wantErr bool
	}{
		{
			name: "default configuration",
			wantCfg: Configuration{
				Logging: Logger{
					Level: "info",
				},
				Server: Server{
					Port: 8079,
				},
				Vici: Vici{
					Network: "tcp",
					Host:    "localhost",
					Port:    4502,
				},
			},
		},
		{
			name: "full configuration",
			rawCfg: `# Logger configuration
logging:
  level: DEBUG
server:
  port: 8077
vici:
  network: udp
  host: 1.2.3.4
  port: 8080
`,
			wantCfg: Configuration{
				Logging: Logger{
					Level: "DEBUG",
				},
				Server: Server{
					Port: 8077,
				},
				Vici: Vici{
					Network: "udp",
					Host:    "1.2.3.4",
					Port:    8080,
				},
			},
		},
		{
			name:    "invalid configuration",
			rawCfg:  `sth wrong`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := os.CreateTemp("/tmp", "ipsec-prometheus-exporter-*.yaml")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(file.Name())
			if err := os.WriteFile(file.Name(), []byte(tt.rawCfg), fs.ModePerm); err != nil {
				t.Fatal(err)
			}
			viper.Reset()
			viper.SetConfigFile(file.Name())

			gotCfg, err := Parse()
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCfg, tt.wantCfg) {
				t.Errorf("Parse() gotCfg = %v, want %v", gotCfg, tt.wantCfg)
			}
		})
	}
}
