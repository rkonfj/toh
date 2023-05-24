package server

import (
	"encoding/json"
	"net/http"

	"github.com/rkonfj/toh/server/acl"
	"github.com/rkonfj/toh/server/api"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type TrafficEvent struct {
	Key, ClientIP, RemoteAddr, Network string
	In, Out                            int64
}

type TrafficEventConsumer func(e *TrafficEvent)

func (s *TohServer) runTrafficEventConsumeLoop() {
	for e := range s.trafficEventChan {
		if e.In == 0 && e.Out == 0 {
			continue
		}
		logrus.
			WithField("stats_in_bytes", e.In).
			WithField("stats_out_bytes", e.Out).
			WithField("stats_key", e.Key).
			WithField("stats_net", e.Network).
			WithField("stats_in", e.ClientIP).
			WithField("stats_out", e.RemoteAddr).
			Info()
		s.acl.UpdateBytesUsage(e.Key, uint64(e.In), uint64(e.Out))
	}
}

func (s *TohServer) HandleShowStats(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(spec.HeaderHandshakeKey)
	clientIP := spec.RealIP(r)
	err := s.acl.CheckKey(apiKey)
	if err == acl.ErrInvalidKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	logrus.Debugf("ip %s query %s stats", clientIP, apiKey)
	limit := s.acl.GetLimit(apiKey)
	usage := s.acl.GetUsage(apiKey)
	stats := api.Stats{
		BytesUsage: usage,
	}
	if len(limit.Bytes) > 0 {
		stats.BytesLimit = limit.Bytes
	}
	if len(limit.InBytes) > 0 {
		stats.InBytesLimit = limit.InBytes
	}
	if len(limit.OutBytes) > 0 {
		stats.OutBytesLimit = limit.OutBytes
	}
	stats.Status = "ok"

	if err != nil {
		stats.Status = err.Error()
	}
	json.NewEncoder(w).Encode(stats)
}
