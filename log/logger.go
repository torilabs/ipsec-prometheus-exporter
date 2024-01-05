package log

import (
	"github.com/torilabs/ipsec-prometheus-exporter/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger *zap.SugaredLogger

func init() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	Logger = logger.Sugar()
}

func Setup(cfg config.Configuration) error {
	var level zapcore.Level

	if err := level.Set(cfg.Logging.Level); err != nil {
		return err
	}

	logCfg := zap.NewProductionConfig()
	logCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logCfg.Level.SetLevel(level)

	logger, err := logCfg.Build()
	if err != nil {
		return err
	}

	Logger = logger.Sugar()

	return nil
}
