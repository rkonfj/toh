package spec

import "os"

type ConfigFileWriter struct {
	f *os.File
}

func NewConfigWriter(f *os.File) *ConfigFileWriter {
	return &ConfigFileWriter{f: f}
}

func (w *ConfigFileWriter) Write(p []byte) (n int, err error) {
	os.Stdout.Write(p)
	return w.f.Write(p)
}
