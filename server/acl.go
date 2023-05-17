package server

import (
	"encoding/json"
	"errors"
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
	Name       string          `json:"name"`
	Key        string          `json:"key"`
	Limit      *Limit          `json:"limit,omitempty"`
	BytesUsage *api.BytesUsage `json:"bytesUsage,omitempty"`
}

type Limit struct {
	Bytes     string   `json:"bytes,omitempty"`
	InBytes   string   `json:"inBytes,omitempty"`
	OutBytes  string   `json:"outBytes,omitempty"`
	Whitelist []string `json:"whitelist,omitempty"`
	Blacklist []string `json:"blacklist,omitempty"`
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

func NewACL(aclPath string) (*ACL, error) {
	acl := &ACL{
		keys:        make(map[string]*key),
		stoFilePath: aclPath,
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
			return nil, err
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
		if k.Limit != nil {
			if k.Limit.Bytes != "" {
				b, err := humanize.ParseBytes(k.Limit.Bytes)
				if err != nil {
					return nil, err
				}
				ke.bytesLimit = b
			}
			if k.Limit.InBytes != "" {
				b, err := humanize.ParseBytes(k.Limit.InBytes)
				if err != nil {
					return nil, err
				}
				ke.inBytesLimit = b
			}
			if k.Limit.OutBytes != "" {
				b, err := humanize.ParseBytes(k.Limit.OutBytes)
				if err != nil {
					return nil, err
				}
				ke.outBytesLimit = b
			}
			ke.blacklist = k.Limit.Blacklist
			ke.whitelist = k.Limit.Whitelist
		}
	}
	logrus.Infof("acl: load %d keys", len(acl.keys))
	go acl.aclPersistLoop()
	return acl, nil
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
