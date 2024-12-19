package log

import (
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

func Setup(rawLevel string) error {
	if rawLevel == "" {
		rawLevel = "info"
	}
	var level zapcore.Level
	if err := level.Set(rawLevel); err != nil {
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
