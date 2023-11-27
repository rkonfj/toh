package admin

import (
	"encoding/json"
	"net/http"

	"github.com/rkonfj/toh/server/acl"
	"github.com/rkonfj/toh/server/api"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

type AdminAPI struct {
	ACL *acl.ACL
}

func (s *AdminAPI) Register(mux *http.ServeMux) {
	if !s.ACL.AdminEnabled() {
		return
	}
	mux.HandleFunc("/admin/acl/key", s.withAuth(s.HandleKey))
	mux.HandleFunc("/admin/acl/limit", s.withAuth(s.HandleLimit))
	mux.HandleFunc("/admin/acl/usage", s.withAuth(s.HandleUsage))
	mux.HandleFunc("/admin/acl", s.withAuth(s.HandleShowACL))
	logrus.Info("admin api(/admin/**) is enabled")
}

func (s *AdminAPI) withAuth(handle func(http.ResponseWriter, *http.Request)) func(
	http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.ACL.IsAdminAccess(r.Header.Get(spec.HeaderHandshakeKey)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handle(w, r)
	}
}

func (s *AdminAPI) HandleKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		name := r.URL.Query().Get("name")
		key := s.ACL.NewKey(name)
		w.Write([]byte(key))
	case http.MethodDelete:
		key := r.URL.Query().Get("key")
		if len(key) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("required key parameter not found in url"))
			return
		}
		s.ACL.DelKey(key)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *AdminAPI) HandleLimit(w http.ResponseWriter, r *http.Request) {
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
		err = s.ACL.Limit(key, &l)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		}
	case http.MethodGet:
		l := s.ACL.GetLimit(key)
		json.NewEncoder(w).Encode(l)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *AdminAPI) HandleUsage(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("required key parameter not found in url"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		usage := s.ACL.GetUsage(key)
		json.NewEncoder(w).Encode(usage)
	case http.MethodDelete:
		s.ACL.DelUsage(key)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *AdminAPI) HandleShowACL(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.ACL.Storage().Keys)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
