package config

import ebpf_config "github.com/cloudflare/ebpf_exporter/config"

// Config describes the configuration of the entire sidecar
type Config struct {
	Programs []Program `yaml:"programs"`
}

// Attachment describes a program to attach to
type Attachment struct {
	BinaryName string `yaml:"binary_name"`
}

// Program describes an eBPF program
type Program struct {
	ebpf_config.Program `yaml:",inline"`
	USDT                map[string]string `yaml:"usdt"`
	Attachment          Attachment        `yaml:"attachment"`
}
