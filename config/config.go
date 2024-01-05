package config

import (
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type Logger struct {
	Level string
}

type Server struct {
	Port int
}

type Vici struct {
	Network string
	Host    string
	Port    int
}

type Configuration struct {
	Logging Logger
	Server  Server
	Vici    Vici
}

func Parse() (cfg Configuration, err error) {
	if viper.ConfigFileUsed() != "" {
		if err := viper.ReadInConfig(); err != nil {
			return cfg, errors.Wrap(err, "failed to read configuration")
		}
	}

	setDefaults()

	if err := viper.Unmarshal(&cfg); err != nil {
		return cfg, errors.Wrap(err, "failed to deserialize config")
	}

	return cfg, nil
}

func setDefaults() {
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("server.port", 8079)
	viper.SetDefault("vici.network", "tcp")
	viper.SetDefault("vici.host", "localhost")
	viper.SetDefault("vici.port", 4502)
}
