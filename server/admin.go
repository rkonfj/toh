package server

import (
	"encoding/json"
	"net/http"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

func (s *TohServer) registerAdminAPIIfEnabled() {
	if s.options.Admin == "" {
		return
	}
	http.HandleFunc("/admin/key", s.HandleAdminKey)
	http.HandleFunc("/admin/limit", s.HandleAdminLimit)
	logrus.Info("admin api(/admin/**) is enabled")
}

func (s *TohServer) HandleAdminKey(w http.ResponseWriter, r *http.Request) {
	if !s.acl.IsAdminAccess(r.Header.Get(spec.HeaderHandshakeKey)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		name := r.URL.Query().Get("name")
		key := s.acl.NewKey(name)
		w.Write([]byte(key))
	case http.MethodDelete:
		key := r.URL.Query().Get("key")
		if len(key) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("required key parameter not found in url"))
			return
		}
		s.acl.DelKey(key)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *TohServer) HandleAdminLimit(w http.ResponseWriter, r *http.Request) {
	if !s.acl.IsAdminAccess(r.Header.Get(spec.HeaderHandshakeKey)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		if r.Body == nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing body"))
			return
		}
		var l Limit
		err := json.NewDecoder(r.Body).Decode(&l)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		key := r.URL.Query().Get("key")
		if key == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("required key parameter not found in url"))
			return
		}
		err = s.acl.Limit(key, &l)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
