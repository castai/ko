package config

import (
	"bytes"
	"fmt"
	"os"

	"github.com/castai/ko/pkg/conntest"
	"github.com/castai/ko/pkg/tracer"
	"gopkg.in/yaml.v3"
)

// Config is the shared agent configuration. Both the node agent and the
// cluster agent read the same file format.
type Config struct {
	Exporters []Exporter      `yaml:"exporters"`
	Tracer    TracerConfig    `yaml:"tracer"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	ConnTest  conntest.Config `yaml:"conntest"`
}

// MetricsConfig configures the agent's Prometheus /metrics endpoint.
// An empty addr disables it.
type MetricsConfig struct {
	Addr string `yaml:"addr"`
}

// TracerConfig configures the eBPF connection tracer.
type TracerConfig struct {
	// Filters select which connections the tracer reports.
	Filters tracer.Filter `yaml:"filters"`
}

type Exporter struct {
	Name string `yaml:"name"`
}

// Default returns the configuration used when no config file is provided.
func Default() Config {
	return Config{
		Exporters: []Exporter{{Name: "stdout"}},
	}
}

// Load reads the config file at path. An empty path returns Default.
func Load(path string) (Config, error) {
	if path == "" {
		return Default(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	return Parse(data)
}

// Parse decodes config YAML strictly: unknown fields are rejected instead of
// being silently ignored.
func Parse(data []byte) (Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}
