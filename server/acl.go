package server

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/uuid"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

var (
	ErrInvalidKey     error = errors.New("invalid key")
	ErrInDataLimited  error = errors.New("network in-data reached the limit")
	ErrOutDataLimited error = errors.New("network out-data reached the limit")
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
	Name          string      `json:"name"`
	Key           string      `json:"key"`
	BytesLimit    string      `json:"bytesLimit,omitempty"`
	InBytesLimit  string      `json:"inBytesLimit,omitempty"`
	OutBytesLimit string      `json:"outBytesLimit,omitempty"`
	BytesUsage    *BytesUsage `json:"bytesUsage,omitempty"`
}

type BytesUsage struct {
	In  uint64 `json:"in"`
	Out uint64 `json:"out"`
}

type key struct {
	bytesLimit, inBytesLimit, outBytesLimit uint64
	bytesUsage                              *BytesUsage
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
		logrus.Infof("initializing ack file %s", aclPath)
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
			bytesUsage: &BytesUsage{},
		}
		if k.BytesUsage != nil {
			ke.bytesUsage = k.BytesUsage
		}
		acl.keys[k.Key] = ke
		if k.BytesLimit != "" {
			b, err := humanize.ParseBytes(k.BytesLimit)
			if err != nil {
				return nil, err
			}
			ke.bytesLimit = b
		}
		if k.InBytesLimit != "" {
			b, err := humanize.ParseBytes(k.InBytesLimit)
			if err != nil {
				return nil, err
			}
			ke.inBytesLimit = b
		}
		if k.OutBytesLimit != "" {
			b, err := humanize.ParseBytes(k.OutBytesLimit)
			if err != nil {
				return nil, err
			}
			ke.outBytesLimit = b
		}
	}
	logrus.Infof("acl: load %d keys", len(acl.keys))
	go acl.aclPersistLoop()
	return acl, nil
}

func (a *ACL) Check(key string) error {
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
