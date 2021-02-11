package server

import (
	"fmt"
	"github.com/josecv/ebpf-usdt-sidecar/pkg/config"
	"github.com/josecv/ebpf-usdt-sidecar/pkg/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

// Serve starts the server
func Serve(listenAddr, metricsPath string, config config.Config) error {
	e := exporter.New(config)
	err := e.Attach()
	if err != nil {
		return fmt.Errorf("Error attaching probes: %s", err)
	}
	err = prometheus.Register(e)
	if err != nil {
		return fmt.Errorf("Error registering exporter: %s", err)
	}
	http.Handle(metricsPath, promhttp.Handler())
	err = http.ListenAndServe(listenAddr, nil)
	return err
}
