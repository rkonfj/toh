package spec

import (
	"context"
	"errors"
	"net"
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
	ErrAuth = errors.New("unauthorized, invalid ToH key")
)

// Dial describe the dial func
type Dial func(ctx context.Context, addr string) (net.Conn, error)