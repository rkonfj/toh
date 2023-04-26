package server

import (
	"github.com/rkonfj/toh/socks5"
	"github.com/sirupsen/logrus"
)

func logTrafficEvent(e *socks5.TrafficEvent) {
	if e.In == 0 && e.Out == 0 {
		return
	}
	logrus.WithField("stats.toh", e.DialerName).
		WithField("stats.in_bytes", e.In).
		WithField("stats.out_bytes", e.Out).
		WithField("stats.in", e.LocalAddr).
		WithField("stats.out", e.RemoteAddr).
		Info()
}
