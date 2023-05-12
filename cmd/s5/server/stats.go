package server

import (
	"strings"
	"time"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

func logTrafficEvent(e *spec.TrafficEvent) {
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

func healthcheck(server *Server, url string) {
	if strings.TrimSpace(url) == "" {
		server.latency = time.Duration(0)
		return
	}
	for {
		t1 := time.Now()
		_, err := server.httpClient.Get(url)
		if err != nil {
			server.latency = server.httpClient.Timeout
		} else {
			server.latency = time.Since(t1)
		}
		time.Sleep(15 * time.Second)
	}
}
