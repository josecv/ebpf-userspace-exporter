package exporter

import (
	"fmt"
	ebpf_config "github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/decoder"
	"github.com/iovisor/gobpf/bcc"
	"github.com/josecv/ebpf-userspace-exporter/pkg/config"
	"github.com/josecv/ebpf-userspace-exporter/pkg/process"
	"github.com/josecv/ebpf-userspace-exporter/pkg/usdt"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"strconv"
)

// This file is taken almost verbatim from cloudflare/ebpf_exporter at https://github.com/cloudflare/ebpf_exporter/blob/master/exporter/exporter.go
// Copyright CloudFlare and Aaron Westendorf
// Licensed under MIT license

const prometheusNamespace = "usdt_exporter"

// Exporter is the metrics exporter itself
type Exporter struct {
	config              config.Config
	modules             map[string]map[int]*bcc.Module
	usdtContexts        map[string]map[int]*usdt.Context
	ksyms               map[uint64]string
	enabledProgramsDesc *prometheus.Desc
	descs               map[string]map[string]*prometheus.Desc
	decoders            *decoder.Set
}

// New creates a new exporter with the provided config
func New(config config.Config) *Exporter {
	enabledProgramsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "enabled_programs"),
		"The set of enabled programs",
		[]string{"name", "pid"},
		nil,
	)

	return &Exporter{
		config:              config,
		modules:             map[string]map[int]*bcc.Module{},
		usdtContexts:        map[string]map[int]*usdt.Context{},
		ksyms:               map[uint64]string{},
		enabledProgramsDesc: enabledProgramsDesc,
		descs:               map[string]map[string]*prometheus.Desc{},
		decoders:            decoder.NewSet(),
	}
}

// Attach enables usdt probes, then attaches the corresponding uprobes
func (e *Exporter) Attach() error {
	processFinder, err := process.NewFinder()
	if err != nil {
		return err
	}
	for _, program := range e.config.Programs {
		procs, err := processFinder.FindByBinaryName(program.Attachment.BinaryName)
		if err != nil {
			return fmt.Errorf("Error searching for process with binary %s for ebpf program %s", program.Attachment.BinaryName, program.Name)
		}
		if len(procs) == 0 {
			return fmt.Errorf("No process for binary %s found (ebpf program %s)", program.Attachment.BinaryName, program.Name)
		}
		for _, proc := range procs {
			pid := proc.PID
			usdtContext, err := usdt.NewContext(pid, program.Code, program.Cflags)
			if err != nil {
				return fmt.Errorf("Can't initialize usdt context for %s: %s", program.Name, err)
			}
			for probe, fnName := range program.USDT {
				zap.S().Debugf("Enabling %s for %s...", fnName, probe)
				err := usdtContext.EnableProbe(probe, fnName)
				if err != nil {
					return err
				}
				zap.S().Debugf("Function %s enabled for probe %s", fnName, probe)
			}
			module, err := usdtContext.CompileModule()
			if err != nil {
				return err
			}
			zap.S().Infof("Program %s loaded", program.Name)
			if _, ok := e.modules[program.Name]; !ok {
				e.modules[program.Name] = make(map[int]*bcc.Module)
				e.usdtContexts[program.Name] = make(map[int]*usdt.Context)
			}
			e.modules[program.Name][pid] = module
			e.usdtContexts[program.Name][pid] = usdtContext
		}
	}
	return nil
}

// Close releases any resources that the exporter is holding on to.
func (e *Exporter) Close() {
	for _, byPid := range e.usdtContexts {
		for _, context := range byPid {
			context.Close()
		}
	}
}

// Describe satisfies prometheus.Collector interface by sending descriptions
// for all metrics the exporter can possibly report
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	addDescs := func(programName string, name string, help string, labels []ebpf_config.Label) {
		if _, ok := e.descs[programName][name]; !ok {
			labelNames := []string{}

			for _, label := range labels {
				labelNames = append(labelNames, label.Name)
			}
			labelNames = append(labelNames, "pid")

			e.descs[programName][name] = prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", name), help, labelNames, nil)
		}

		ch <- e.descs[programName][name]
	}

	ch <- e.enabledProgramsDesc

	for _, program := range e.config.Programs {
		if _, ok := e.descs[program.Name]; !ok {
			e.descs[program.Name] = map[string]*prometheus.Desc{}
		}

		for _, counter := range program.Metrics.Counters {
			addDescs(program.Name, counter.Name, counter.Help, counter.Labels)
		}

		for _, histogram := range program.Metrics.Histograms {
			addDescs(program.Name, histogram.Name, histogram.Help, histogram.Labels[0:len(histogram.Labels)-1])
		}
	}
}

// Collect satisfies prometheus.Collector interface and sends all metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		for pid := range e.usdtContexts[program.Name] {
			ch <- prometheus.MustNewConstMetric(e.enabledProgramsDesc, prometheus.GaugeValue, 1, program.Name, strconv.Itoa(pid))
		}
	}

	e.collectCounters(ch)
	e.collectHistograms(ch)
}

// collectCounters sends all known counters to prometheus
func (e *Exporter) collectCounters(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		for _, counter := range program.Metrics.Counters {
			for pid, module := range e.modules[program.Name] {
				tableValues, err := e.tableValues(module, counter.Table, counter.Labels)
				if err != nil {
					zap.S().Errorf("Error getting table %q values for metric %q of program %q: %s", counter.Table, counter.Name, program.Name, err)
					continue
				}

				desc := e.descs[program.Name][counter.Name]

				for _, metricValue := range tableValues {
					labels := metricValue.labels
					labels = append(labels, strconv.Itoa(pid))
					ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, metricValue.value, labels...)
				}
			}
		}
	}
}

// collectHistograms sends all known historams to prometheus
func (e *Exporter) collectHistograms(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		for _, histogram := range program.Metrics.Histograms {
			for pid, module := range e.modules[program.Name] {
				skip := false

				histograms := map[string]histogramWithLabels{}

				tableValues, err := e.tableValues(module, histogram.Table, histogram.Labels)
				if err != nil {
					zap.S().Errorf("Error getting table %q values for metric %q of program %q: %s", histogram.Table, histogram.Name, program.Name, err)
					continue
				}

				// Taking the last label and using int as bucket delimiter, for example:
				//
				// Before:
				// * [sda, read, 1ms] -> 10
				// * [sda, read, 2ms] -> 2
				// * [sda, read, 4ms] -> 5
				//
				// After:
				// * [sda, read] -> {1ms -> 10, 2ms -> 2, 4ms -> 5}
				for _, metricValue := range tableValues {
					labels := metricValue.labels[0 : len(metricValue.labels)-1]
					labels = append(labels, strconv.Itoa(pid))

					key := fmt.Sprintf("%#v", labels)

					if _, ok := histograms[key]; !ok {
						histograms[key] = histogramWithLabels{
							labels:  labels,
							buckets: map[float64]uint64{},
						}
					}

					leUint, err := strconv.ParseUint(metricValue.labels[len(metricValue.labels)-1], 0, 64)
					if err != nil {
						zap.S().Errorf("Error parsing float value for bucket %#v in table %q of program %q: %s", metricValue.labels, histogram.Table, program.Name, err)
						skip = true
						break
					}

					histograms[key].buckets[float64(leUint)] = uint64(metricValue.value)
				}

				if skip {
					continue
				}

				desc := e.descs[program.Name][histogram.Name]

				for _, histogramSet := range histograms {
					buckets, count, sum, err := transformHistogram(histogramSet.buckets, histogram)
					if err != nil {
						zap.S().Errorf("Error transforming histogram for metric %q in program %q: %s", histogram.Name, program.Name, err)
						continue
					}

					// Sum is explicitly set to zero. We only take bucket values from
					// eBPF tables, which means we lose precision and cannot calculate
					// average values from histograms anyway.
					// Lack of sum also means we cannot have +Inf bucket, only some finite
					// value bucket, eBPF programs must cap bucket values to work with this.
					ch <- prometheus.MustNewConstHistogram(desc, count, sum, buckets, histogramSet.labels...)
				}
			}
		}
	}
}

// tableValues returns values in the requested table to be used in metircs
func (e *Exporter) tableValues(module *bcc.Module, tableName string, labels []ebpf_config.Label) ([]metricValue, error) {
	values := []metricValue{}

	table := bcc.NewTable(module.TableId(tableName), module)
	iter := table.Iter()

	for iter.Next() {
		key := iter.Key()
		raw, err := table.KeyBytesToStr(key)
		if err != nil {
			return nil, fmt.Errorf("error decoding key %v", key)
		}

		mv := metricValue{
			raw:    raw,
			labels: make([]string, len(labels)),
		}

		mv.labels, err = e.decoders.DecodeLabels(key, labels)
		if err != nil {
			if err == decoder.ErrSkipLabelSet {
				continue
			}

			return nil, err
		}

		mv.value = float64(bcc.GetHostByteOrder().Uint64(iter.Leaf()))

		values = append(values, mv)
	}

	return values, nil
}

// metricValue is a row in a kernel map
type metricValue struct {
	// raw is a raw key value provided by kernel
	raw string
	// labels are decoded from the raw key
	labels []string
	// value is the kernel map value
	value float64
}
