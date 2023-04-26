package server

import (
	"github.com/rkonfj/toh/socks5"
	"github.com/sirupsen/logrus"
)

func logTrafficEvent(e *socks5.TrafficEvent) {
	if e.In == 0 && e.Out == 0 {
		return
	}
	logrus.WithField("stats_toh", e.DialerName).
		WithField("stats_net", e.Network).
		WithField("stats_in_bytes", e.In).
		WithField("stats_out_bytes", e.Out).
		WithField("stats_in", e.LocalAddr).
		WithField("stats_out", e.RemoteAddr).
		Info()
}
