package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/uuid"
	"github.com/rkonfj/toh/server/api"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

var (
	ErrInvalidKey     error = errors.New("invalid key")
	ErrInDataLimited  error = errors.New("network in-data reached the limit")
	ErrOutDataLimited error = errors.New("network out-data reached the limit")

	ErrServiceAccessDenied error = errors.New("service access denied")
)

type ACL struct {
	adminKey                  string
	keys                      map[string]*key
	stoFilePath               string
	sto                       *ACLStorage
	stoUpdatePendingCount     int64
	stoUpdatePendingCountLock sync.Mutex
}

type ACLStorage struct {
	Keys []*Key `json:"keys"`
}

type Key struct {
	Name       string          `json:"name,omitempty"`
	Key        string          `json:"key"`
	Limit      *api.Limit      `json:"limit,omitempty"`
	BytesUsage *api.BytesUsage `json:"bytesUsage,omitempty"`
}

type key struct {
	bytesLimit, inBytesLimit, outBytesLimit uint64
	bytesUsage                              *api.BytesUsage
	whitelist, blacklist                    []string
}

func (k *key) inBytesLimited() bool {
	if k.inBytesLimit > 0 {
		return k.bytesUsage.In >= k.inBytesLimit
	}
	if k.bytesLimit <= 0 {
		return false
	}
	if k.outBytesLimit > 0 {
		return k.bytesUsage.In >= k.bytesLimit-k.outBytesLimit
	}
	return k.bytesUsage.In+k.bytesUsage.Out >= k.bytesLimit
}

func (k *key) outBytesLimited() bool {
	if k.outBytesLimit > 0 {
		return k.bytesUsage.Out >= k.outBytesLimit
	}
	if k.bytesLimit <= 0 {
		return false
	}
	if k.inBytesLimit > 0 {
		return k.bytesUsage.Out >= k.bytesLimit-k.inBytesLimit
	}
	return k.bytesUsage.In+k.bytesUsage.Out >= k.bytesLimit
}

func NewACL(aclPath, adminKey string) (*ACL, error) {
	if len(adminKey) > 0 && len(adminKey) < 16 {
		return nil, errors.New("the minimum admin key is 16 characters")
	}
	acl := &ACL{
		keys:        make(map[string]*key),
		stoFilePath: aclPath,
		adminKey:    adminKey,
	}

	var sto ACLStorage
	aclF, err := os.Open(aclPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		logrus.Infof("initializing acl file %s", aclPath)
		aclF, err = os.OpenFile(aclPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		defer aclF.Close()
		sto = ACLStorage{
			Keys: []*Key{{Name: "default", Key: uuid.New().String()}},
		}
		enc := json.NewEncoder(spec.NewConfigWriter(aclF))
		enc.SetIndent("", "    ")
		enc.Encode(sto)
	} else {
		defer aclF.Close()
		err = json.NewDecoder(aclF).Decode(&sto)
		if err != nil {
			return nil, fmt.Errorf("acl file: %s", err)
		}
	}

	acl.sto = &sto
	for _, k := range sto.Keys {
		ke := &key{
			bytesUsage: &api.BytesUsage{},
		}
		if k.BytesUsage != nil {
			ke.bytesUsage = k.BytesUsage
		}
		acl.keys[k.Key] = ke
		acl.applyACLKeyLimit(ke, k.Limit)
	}
	logrus.Infof("acl: load %d keys", len(acl.keys))
	go acl.aclPersistLoop()
	return acl, nil
}

func (a *ACL) IsAdminAccess(key string) bool {
	return a.adminKey != "" && a.adminKey == key
}

func (a *ACL) CheckKey(key string) error {
	if k, ok := a.keys[key]; ok {
		if k.inBytesLimited() {
			return ErrInDataLimited
		}
		if k.outBytesLimited() {
			return ErrOutDataLimited
		}
		return nil
	}
	return ErrInvalidKey
}

func (a *ACL) Check(key, network, addr string) error {
	err := a.CheckKey(key)
	if err != nil {
		return err
	}
	k := a.keys[key]
	if k.whitelist != nil {
		for _, a := range k.whitelist {
			toMatch := strings.Split(strings.TrimSpace(a), "/")
			if len(toMatch) == 1 && toMatch[0] == addr {
				return nil
			}
			if len(toMatch) == 2 && toMatch[0] == addr && toMatch[1] == network {
				return nil
			}
		}
		return ErrServiceAccessDenied
	}

	if k.blacklist != nil {
		for _, a := range k.blacklist {
			toMatch := strings.Split(strings.TrimSpace(a), "/")
			if len(toMatch) == 1 && toMatch[0] == addr {
				return ErrServiceAccessDenied
			}
			if len(toMatch) == 2 && toMatch[0] == addr && toMatch[1] == network {
				return ErrServiceAccessDenied
			}
		}
	}
	return nil
}

func (a *ACL) UpdateBytesUsage(key string, in, out uint64) {
	if k, ok := a.keys[key]; ok {
		k.bytesUsage.In += in
		k.bytesUsage.Out += out
		a.stoUpdatePendingCountLock.Lock()
		a.stoUpdatePendingCount++
		a.stoUpdatePendingCountLock.Unlock()
	}
}

func (a *ACL) NewKey(name string) string {
	k := uuid.NewString()

	ke := &Key{
		Name: name,
		Key:  k,
	}
	a.keys[k] = &key{
		bytesUsage: &api.BytesUsage{},
	}
	a.stoUpdatePendingCountLock.Lock()
	defer a.stoUpdatePendingCountLock.Unlock()
	a.sto.Keys = append(a.sto.Keys, ke)
	a.stoUpdatePendingCount++
	return k
}

func (a *ACL) DelKey(key string) {
	a.stoUpdatePendingCountLock.Lock()
	defer a.stoUpdatePendingCountLock.Unlock()
	delete(a.keys, key)
	a.stoUpdatePendingCount++
	for i, v := range a.sto.Keys {
		if v.Key == key {
			a.sto.Keys = append(a.sto.Keys[:i], a.sto.Keys[i+1:]...)
		}
	}
}

// Limit replace key's limit
func (a *ACL) Limit(key string, l *api.Limit) error {
	a.stoUpdatePendingCountLock.Lock()
	defer a.stoUpdatePendingCountLock.Unlock()
	a.stoUpdatePendingCount++
	if k, ok := a.keys[key]; ok {
		err := a.applyACLKeyLimit(k, l)
		if err != nil {
			return err
		}
		for _, ke := range a.sto.Keys {
			if ke.Key == key {
				ke.Limit = l
			}
		}
	}
	return nil
}

func (a *ACL) GetLimit(key string) *api.Limit {
	for _, ke := range a.sto.Keys {
		if ke.Key == key {
			if ke.Limit == nil {
				return &api.Limit{}
			}
			return ke.Limit
		}
	}
	return &api.Limit{}
}

func (a *ACL) GetUsage(key string) *api.BytesUsage {
	if k, ok := a.keys[key]; ok {
		return k.bytesUsage
	}
	return &api.BytesUsage{}
}

func (a *ACL) DelUsage(key string) {
	a.stoUpdatePendingCountLock.Lock()
	defer a.stoUpdatePendingCountLock.Unlock()
	a.stoUpdatePendingCount++
	if k, ok := a.keys[key]; ok {
		k.bytesUsage = &api.BytesUsage{}
	}
}

func (a *ACL) applyACLKeyLimit(ke *key, l *api.Limit) error {
	if l != nil {
		if l.Bytes != "" {
			b, err := humanize.ParseBytes(l.Bytes)
			if err != nil {
				return err
			}
			ke.bytesLimit = b
		}
		if l.InBytes != "" {
			b, err := humanize.ParseBytes(l.InBytes)
			if err != nil {
				return err
			}
			ke.inBytesLimit = b
		}
		if l.OutBytes != "" {
			b, err := humanize.ParseBytes(l.OutBytes)
			if err != nil {
				return err
			}
			ke.outBytesLimit = b
		}
		ke.blacklist = l.Blacklist
		ke.whitelist = l.Whitelist
	}
	return nil
}

func (a *ACL) persist() error {
	aclF, err := os.OpenFile(a.stoFilePath, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer aclF.Close()
	err = aclF.Truncate(0)
	if err != nil {
		return err
	}
	for _, k := range a.sto.Keys {
		if key, ok := a.keys[k.Key]; ok {
			k.BytesUsage = key.bytesUsage
		}
	}
	enc := json.NewEncoder(aclF)
	enc.SetIndent("", "    ")
	enc.Encode(a.sto)
	return nil
}

func (a *ACL) aclPersistLoop() {
	for {
		time.Sleep(2 * time.Second)
		if a.stoUpdatePendingCount > 0 {
			a.stoUpdatePendingCountLock.Lock()
			a.stoUpdatePendingCount = 0
			a.stoUpdatePendingCountLock.Unlock()
			if err := a.persist(); err != nil {
				logrus.Error(err)
			}
		}
	}
}
