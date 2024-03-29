package client

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type ConnEntry struct {
	Proto      string `json:"proto"`
	LocalAddr  string `json:"localAddr"`
	RemoteAddr string `json:"remoteAddr"`
	RemoteHost string `json:"remoteHost"`
	Nonce      byte   `json:"nonce"`
	lastRWTime time.Time
	ct         *Conntrack
}

func (c *ConnEntry) add() {
	c.ct.addConn(c)
	logrus.Debugf("tracking %s://%s", c.Proto, c.RemoteAddr)
}

func (c *ConnEntry) remove() {
	c.ct.removeConn(c)
	logrus.Debugf("stop tracking %s://%s", c.Proto, c.RemoteAddr)
}

type Conntrack struct {
	lock    sync.Mutex
	entries map[*ConnEntry]struct{}
}

func NewConntrack() *Conntrack {
	return &Conntrack{
		entries: make(map[*ConnEntry]struct{}),
	}
}

func (ct *Conntrack) addConn(e *ConnEntry) {
	ct.lock.Lock()
	defer ct.lock.Unlock()
	ct.entries[e] = struct{}{}
}

func (ct *Conntrack) removeConn(e *ConnEntry) {
	ct.lock.Lock()
	defer ct.lock.Unlock()
	delete(ct.entries, e)
}

func (ct *Conntrack) List() []ConnEntry {
	entries := make([]ConnEntry, 0)
	for e := range ct.entries {
		entries = append(entries, *e)
	}
	return entries
}
