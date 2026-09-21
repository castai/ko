package exporters

import (
	"fmt"

	"github.com/castai/ko/pkg/config"
)

// Build creates the exporters configured in cfg. Unknown exporter names are
// rejected so a bad config fails fast at startup.
func Build(cfg config.Config) ([]Exporter, error) {
	res := make([]Exporter, 0, len(cfg.Exporters))
	for _, ec := range cfg.Exporters {
		switch ec.Name {
		case "stdout":
			res = append(res, NewStdoutExporter())
		default:
			return nil, fmt.Errorf("unknown exporter %q", ec.Name)
		}
	}
	return res, nil
}
