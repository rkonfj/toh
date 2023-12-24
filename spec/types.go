package spec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// LogField log filed
type LogField int

const (
	AppAddr LogField = iota
)

func (c LogField) String() string {
	switch c {
	case AppAddr:
		return "appaddr"
	default:
		return "unknown"
	}
}

var (
	ErrAuth                = errors.New("authentication failed! invalid/limited ToH key")
	ErrDNSTypeANotFound    = errors.New("type A record not found")
	ErrDNSTypeAAAANotFound = errors.New("type AAAA record not found")
	ErrDNSRecordNotFound   = errors.New("dns record not found")

	ErrUnsupportNetwork = errors.New("unsupport network")

	HeaderHandshakeKey   = "X-Toh-Key"
	HeaderHandshakeNet   = "X-Toh-Net"
	HeaderHandshakeAddr  = "X-Toh-Addr"
	HeaderHandshakeNonce = "X-Toh-Nonce"
	HeaderEstablishAddr  = "X-Toh-EstAddr"
)

// Dial describe the dial func
type Dial func(ctx context.Context, network, addr string) (net.Conn, error)

// ConfigFileWriter a writer that writes to both files and stdout
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

type ConnectParameters struct {
	URL       *url.URL
	Key       string
	Network   string
	Addr      string
	Header    http.Header
	Keepalive time.Duration
}
