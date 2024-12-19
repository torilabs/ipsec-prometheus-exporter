package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/etherlabsio/healthcheck/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/strongswan/govici/vici"
	"github.com/torilabs/ipsec-prometheus-exporter/log"
	"github.com/torilabs/ipsec-prometheus-exporter/strongswan"
	"go.uber.org/zap"
)

const (
	gracefulShutdownWait = time.Second * 60
	requestTimeout       = time.Second * 30
	readHeaderTimeout    = time.Second * 30
)

var (
	serverPort  = flag.Uint("server-port", 8079, "Server port")
	logLevel    = flag.String("log-level", "info", "Log level")
	viciNetwork = flag.String("vici-network", "tcp", "Vici network (tcp, udp or unix)")
	viciAddr    = flag.String("vici-address", "localhost:4502", "Vici host and port or unix socket path")
)

func main() {
	if err := run(); err != nil {
		log.Logger.With(zap.Error(err)).Error("Terminating the service.")
	}
}

func run() (err error) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	flag.Parse()

	if err := log.Setup(*logLevel); err != nil {
		return err
	}
	defer log.Logger.Sync()

	viciClientFn := func() (strongswan.ViciClient, error) {
		s, err := vici.NewSession(vici.WithAddr(*viciNetwork, *viciAddr))
		if err != nil {
			log.Logger.Warnf("Error connecting to Vici API: %s", err)
		}
		return s, err
	}
	cl := strongswan.NewCollector(viciClientFn)

	checkers := make([]healthcheck.Option, 0)
	checkers = append(checkers, healthcheck.WithChecker("vici", cl))
	if err := prometheus.Register(cl); err != nil {
		return err
	}
	stopFn := startServer(checkers)
	defer stopFn()

	// wait for program to terminate
	<-sigs

	return nil
}

func startServer(checkers []healthcheck.Option) func() {
	mux := http.DefaultServeMux
	mux.Handle("/healthcheck", http.TimeoutHandler(healthcheck.Handler(checkers...), requestTimeout, "request timeout"))
	mux.Handle("/metrics", http.TimeoutHandler(promhttp.Handler(), requestTimeout, "request timeout"))

	s := &http.Server{
		Addr:              fmt.Sprintf(":%d", *serverPort),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	go func() {
		log.Logger.Infof("Starting admin server on port '%v'.", *serverPort)
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Logger.With(zap.Error(err)).Fatalf("Failed to start admin server.")
		}
	}()

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), gracefulShutdownWait)
		defer cancel()
		err := s.Shutdown(ctx)
		if err != nil {
			log.Logger.With(zap.Error(err)).Warn("Error occurred during shutting down servers.")
		}
		log.Logger.Info("Admin server successfully shutdown.")
	}
}
