package main

import (
	"github.com/torilabs/ipsec-prometheus-exporter/cmd"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
	"go.uber.org/zap"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Logger.With(zap.Error(err)).Error("Terminating the service.")
	}
}
