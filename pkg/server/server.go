package server

import (
	"github.com/josecv/ebpf-usdt-sidecar/pkg/config"
	"github.com/josecv/ebpf-usdt-sidecar/pkg/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"net/http"
)

// Serve starts the server
func Serve(listenAddr, metricsPath string, config config.Config) {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	undo := zap.ReplaceGlobals(logger)
	defer undo()

	e := exporter.New(config)
	defer e.Close()
	err = e.Attach()
	if err != nil {
		zap.S().Fatalf("Error attaching probes: %s", err)
	}
	err = prometheus.Register(e)
	if err != nil {
		zap.S().Fatalf("Error registering exporter: %s", err)
	}
	http.Handle(metricsPath, promhttp.Handler())
	zap.S().Infof("Serving metrics at %s%s", listenAddr, metricsPath)
	err = http.ListenAndServe(listenAddr, nil)
	zap.S().Fatal(err)
}
