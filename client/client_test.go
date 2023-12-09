package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkonfj/toh/server"
	"github.com/rkonfj/toh/server/acl"
	"github.com/rkonfj/toh/server/api"
	"github.com/sirupsen/logrus"
)

const serverKey = "9bJF7GcYTS9HJseBcyJoPkWbtRjxnzyxrJ48pohvftJLhoh2MPe"
const serverTmpAddr = "127.0.0.1:9986"

func prepareServer() (cancel func(), err error) {
	aclPath := filepath.Join(os.TempDir(), "acl.json")
	os.Remove(aclPath)

	aclData := acl.ACLStorage{
		Keys: []*api.Key{{Key: serverKey}},
	}

	b, err := json.Marshal(aclData)
	if err != nil {
		return
	}

	err = os.WriteFile(aclPath, b, 0644)
	if err != nil {
		return
	}
	s, err := server.NewTohServer(server.Options{Listen: serverTmpAddr, ACL: aclPath})
	if err != nil {
		return
	}
	logrus.SetLevel(logrus.DebugLevel)
	go func() {
		s.Run()
	}()
	time.Sleep(200 * time.Millisecond)
	return func() {
		s.Shutdown(context.Background())
		os.Remove(aclPath)
	}, nil
}

func TestTCP(t *testing.T) {
	cancel, err := prepareServer()
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	c, err := NewTohClient(Options{
		Server: fmt.Sprintf("ws://%s/ws", serverTmpAddr),
		Key:    serverKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: c.DialContext},
	}

	resp, err := httpClient.Get("https://api64.ipify.org")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)
}

func TestUDP(t *testing.T) {
	cancel, err := prepareServer()
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	c, err := NewTohClient(Options{
		Server: fmt.Sprintf("ws://%s/ws", serverTmpAddr),
		Key:    serverKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	resolver := net.Resolver{
		PreferGo: true,
		Dial:     c.DialContext,
	}

	ips, err := resolver.LookupIP(context.Background(), "ip", "www.baidu.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) == 0 {
		t.Fatal(err)
	}
	fmt.Println(ips)
}
