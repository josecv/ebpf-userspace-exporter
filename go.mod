module github.com/josecv/ebpf-userspace-exporter

go 1.15

replace github.com/iovisor/gobpf => github.com/josecv/gobpf v0.0.0-20210210221433-5d0430002500

require (
	github.com/cloudflare/ebpf_exporter v1.2.3
	github.com/iovisor/gobpf v0.0.0-20200614202714-e6b321d32103
	github.com/mitchellh/go-homedir v1.1.0
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/procfs v0.2.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.0
	go.uber.org/zap v1.13.0
	gopkg.in/yaml.v2 v2.3.0
)
