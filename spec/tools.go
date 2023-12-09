package spec

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/http"
	"strings"
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
		defaultLogger.Debug("real ip resolved", "from", "X-Real-IP", "ip", realIP)
		return realIP
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		defaultLogger.Debug("real ip resolved", "from", "X-Forwarded-For", "ip", realIP)
		return strings.Split(strings.TrimSpace(xff), ",")[0]
	}

	tcpAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	defaultLogger.Debug("real ip resolved", "from", "RemoteAddr", "ip", tcpAddr.IP)
	return tcpAddr.IP.String()
}
