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
