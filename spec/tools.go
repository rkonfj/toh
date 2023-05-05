package spec

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/http"

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
