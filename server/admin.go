package server

import (
	"encoding/json"
	"net/http"

	"github.com/rkonfj/toh/server/api"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

func (s *TohServer) registerAdminAPIIfEnabled() {
	if s.options.AdminKey == "" {
		return
	}
	http.HandleFunc("/admin/acl/key", s.HandleAdminKey)
	http.HandleFunc("/admin/acl/limit", s.HandleAdminLimit)
	http.HandleFunc("/admin/acl/usage", s.HandleAdminUsage)
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
	key := r.URL.Query().Get("key")
	if key == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("required key parameter not found in url"))
		return
	}
	switch r.Method {
	case http.MethodPatch:
		if r.Body == nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing body"))
			return
		}
		var l api.Limit
		err := json.NewDecoder(r.Body).Decode(&l)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		err = s.acl.Limit(key, &l)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		}
	case http.MethodGet:
		l := s.acl.GetLimit(key)
		json.NewEncoder(w).Encode(l)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *TohServer) HandleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if !s.acl.IsAdminAccess(r.Header.Get(spec.HeaderHandshakeKey)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("required key parameter not found in url"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		usage := s.acl.GetUsage(key)
		json.NewEncoder(w).Encode(usage)
	case http.MethodDelete:
		s.acl.DelUsage(key)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
