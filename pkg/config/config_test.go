package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	cfg, err := Parse([]byte(`
exporters:
  - name: stdout
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Exporters) != 1 || cfg.Exporters[0].Name != "stdout" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseTracerFilters(t *testing.T) {
	cfg, err := Parse([]byte(`
exporters: []
tracer:
  filters:
    verify: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Tracer.Filters.Verify {
		t.Fatalf("expected verify filter mode, got %+v", cfg.Tracer)
	}
}

func TestParseTracerCelFilters(t *testing.T) {
	cfg, err := Parse([]byte(`
exporters: []
tracer:
  filters:
    cel:
      - name: prod
        expr: ko_namespace == "production"
      - name: noisy
        expr: ip_in(ko_remote_addr, ko_private_cidrs)
`))
	if err != nil {
		t.Fatal(err)
	}
	cel := cfg.Tracer.Filters.Cel
	if len(cel) != 2 {
		t.Fatalf("expected 2 cel filters, got %+v", cfg.Tracer.Filters)
	}
	if cel[0].Name != "prod" || cel[0].Expr != `ko_namespace == "production"` {
		t.Fatalf("unexpected first filter: %+v", cel[0])
	}
	if cel[1].Name != "noisy" || cel[1].Expr != `ip_in(ko_remote_addr, ko_private_cidrs)` {
		t.Fatalf("unexpected second filter: %+v", cel[1])
	}
	if cfg.Tracer.Filters.Verify {
		t.Fatal("expected verify to default to off")
	}
}

func TestParseKontextSocketPaths(t *testing.T) {
	cfg, err := Parse([]byte(`
exporters: []
kontext:
  socketPaths:
    - /run/containerd/containerd.sock
    - /run/k0s/containerd.sock
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/run/containerd/containerd.sock", "/run/k0s/containerd.sock"}
	if len(cfg.Kontext.SocketPaths) != 2 {
		t.Fatalf("expected 2 socket paths, got %+v", cfg.Kontext)
	}
	for i, path := range want {
		if cfg.Kontext.SocketPaths[i] != path {
			t.Fatalf("expected socket path %s, got %+v", path, cfg.Kontext)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	cfg, err := Parse([]byte(`exporters: []`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Exporters) != 0 {
		t.Fatalf("expected no exporters, got %+v", cfg)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte("expoters: []")); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("exporters:\n  - name: stdout\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Exporters) != 1 || cfg.Exporters[0].Name != "stdout" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadEmptyPathReturnsDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Exporters) != 1 || cfg.Exporters[0].Name != "stdout" {
		t.Fatalf("unexpected default config: %+v", cfg)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/does/not/exist.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
