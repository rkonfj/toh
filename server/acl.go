package server

import (
	"encoding/json"
	"os"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type ACL struct {
	keys map[string]struct{}
}

type ACLStorage struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

func NewACL(aclPath string) (*ACL, error) {
	acl := &ACL{
		keys: map[string]struct{}{},
	}

	var sto ACLStorage
	aclF, err := os.Open(aclPath)
	if err != nil {
		aclF, err = os.OpenFile(aclPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		sto = ACLStorage{
			Keys: []Key{{Name: "system", Key: uuid.New().String()}},
		}
		enc := json.NewEncoder(aclF)
		enc.SetIndent("", "    ")
		enc.Encode(sto)
	} else {
		err = json.NewDecoder(aclF).Decode(&sto)
		if err != nil {
			return nil, err
		}
	}

	for _, k := range sto.Keys {
		acl.keys[k.Key] = struct{}{}
	}
	logrus.Infof("acl: load %d keys", len(acl.keys))
	return acl, nil
}

func (a *ACL) Check(key string) bool {
	if _, ok := a.keys[key]; ok {
		return true
	}
	return false
}
