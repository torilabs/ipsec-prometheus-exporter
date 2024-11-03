package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/etherlabsio/healthcheck/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/strongswan/govici/vici"
	"github.com/torilabs/ipsec-prometheus-exporter/config"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
	"github.com/torilabs/ipsec-prometheus-exporter/strongswan"
	"go.uber.org/zap"
)

var (
	cfgPath string
	cfg     config.Configuration
)

func Execute() error {
	return rootCmd.Execute()
}

var rootCmd = &cobra.Command{
	Use:               "ipsec-prometheus-exporter",
	DisableAutoGenTag: true,
	Short:             "IPsec exporter for Prometheus.",
	Long:              "IPsec Prometheus Exporter exports Strongswan metrics.",
	SilenceErrors:     true,
	SilenceUsage:      true,
	PreRunE: func(cmd *cobra.Command, _ []string) (err error) {
		if err = viper.BindPFlags(cmd.Flags()); err != nil {
			return
		}
		viper.SetConfigFile(cfgPath)

		if cfg, err = config.Parse(); err != nil {
			return err
		}
		return nil
	},
	RunE: func(*cobra.Command, []string) error {
		if err := log.Setup(cfg); err != nil {
			return err
		}
		defer log.Logger.Sync()

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		checkers := make([]healthcheck.Option, 0)

		viciClientFn := func() (strongswan.ViciClient, error) {
			s, err := vici.NewSession(vici.WithAddr(cfg.Vici.Network, fmt.Sprintf("%s:%d", cfg.Vici.Host, cfg.Vici.Port)))
			if err != nil {
				log.Logger.Warnf("Error connecting to Vici API: %s", err)
			}
			return s, err
		}
		cl := strongswan.NewCollector(viciClientFn)
		checkers = append(checkers, healthcheck.WithChecker("vici", cl))
		if err := prometheus.Register(cl); err != nil {
			return err
		}
		startServer(checkers)

		// wait for program to terminate
		<-sigs

		// shutdown
		log.Logger.Info("Shutting down the service.")

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", "", "Path to the config file.")
}

func startServer(checkers []healthcheck.Option) {
	log.Logger.Infof("Starting admin server on port '%v'.", cfg.Server.Port)

	go func() {
		http.Handle("/healthcheck", healthcheck.Handler(checkers...))
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.Server.Port), nil); err != nil && err != http.ErrServerClosed {
			log.Logger.With(zap.Error(err)).Fatalf("Failed to start admin server.")
		}
	}()
}
