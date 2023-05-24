package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rkonfj/toh/spec"
)

type ServerAdminClient struct {
	client           *http.Client
	server, adminKey string
}

func NewServerAdminClient(server, adminKey string) *ServerAdminClient {
	return &ServerAdminClient{
		client:   &http.Client{},
		server:   server,
		adminKey: adminKey,
	}
}

func (c *ServerAdminClient) ACLNewKey(name string) (key string, err error) {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/admin/acl/key", c.server), nil)
	if err != nil {
		return
	}
	req.Header.Add(spec.HeaderHandshakeKey, c.adminKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		err = spec.ErrAuth
		return
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	return string(b), nil
}

func (c *ServerAdminClient) ACLDelKey(key string) (err error) {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/admin/acl/key?key="+key, c.server), nil)
	if err != nil {
		return
	}
	req.Header.Add(spec.HeaderHandshakeKey, c.adminKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode == http.StatusUnauthorized {
		err = spec.ErrAuth
		return
	}
	return
}

func (c *ServerAdminClient) ACLPatchLimit(key string, l *Limit) (err error) {
	body := &bytes.Buffer{}
	err = json.NewEncoder(body).Encode(l)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/admin/acl/limit?key="+key, c.server), body)
	if err != nil {
		return
	}
	req.Header.Add(spec.HeaderHandshakeKey, c.adminKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode == http.StatusUnauthorized {
		err = spec.ErrAuth
		return
	}

	return
}

func (c *ServerAdminClient) ACLGetLimit(key string) (l *Limit, err error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/admin/acl/limit?key="+key, c.server), nil)
	if err != nil {
		return
	}
	req.Header.Add(spec.HeaderHandshakeKey, c.adminKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		err = spec.ErrAuth
		return
	}
	l = &Limit{}
	err = json.NewDecoder(resp.Body).Decode(l)
	return
}

func (c *ServerAdminClient) ACLGetUsage(key string) (usage *BytesUsage, err error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/admin/acl/usage?key="+key, c.server), nil)
	if err != nil {
		return
	}
	req.Header.Add(spec.HeaderHandshakeKey, c.adminKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		err = spec.ErrAuth
		return
	}
	usage = &BytesUsage{}
	err = json.NewDecoder(resp.Body).Decode(usage)
	return
}

func (c *ServerAdminClient) ACLDelUsage(key string) (err error) {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/admin/acl/usage?key="+key, c.server), nil)
	if err != nil {
		return
	}
	req.Header.Add(spec.HeaderHandshakeKey, c.adminKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode == http.StatusUnauthorized {
		err = spec.ErrAuth
		return
	}
	return
}

func (c *ServerAdminClient) ACLShow() (keys []Key, err error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/admin/acl", c.server), nil)
	if err != nil {
		return
	}
	req.Header.Add(spec.HeaderHandshakeKey, c.adminKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		err = spec.ErrAuth
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&keys)
	return
}
