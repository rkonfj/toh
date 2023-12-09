package spec

import (
	"log/slog"
	"os"
)

var defaultLogger = slog.New(slog.NewTextHandler(os.Stdout, nil))

func SetDefaultLogger(logger *slog.Logger) {
	defaultLogger = logger
}
