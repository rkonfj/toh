package spec

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

func Uint16ToBytes(n uint16) []byte {
	bytebuf := &bytes.Buffer{}
	binary.Write(bytebuf, binary.BigEndian, n)
	return bytebuf.Bytes()
}

func Uint32ToBytes(n uint32) []byte {
	bytebuf := &bytes.Buffer{}
	binary.Write(bytebuf, binary.BigEndian, n)
	return bytebuf.Bytes()
}

func BytesToUint16(bys []byte) uint16 {
	bytebuff := bytes.NewBuffer(bys)
	var data uint16
	binary.Read(bytebuff, binary.BigEndian, &data)
	return data
}

func RealIP(r *http.Request) string {
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		logrus.Debugf("resolve real ip from x-real-ip: %s", realIP)
		return realIP
	}

	tcpAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	logrus.Debugf("resolve real ip from remote addr: %s", tcpAddr.IP.String())
	return tcpAddr.IP.String()
}

func ResolveIP(ctx context.Context, dial Dial, addr string) (a string, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	dnsLookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := (&net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dial(ctx, "8.8.8.8:53")
		},
	}).LookupIP(dnsLookupCtx, "ip", host)
	if err != nil {
		return
	}
	return fmt.Sprintf("%s:%s", ips[rand.Intn(len(ips))], port), nil
}
