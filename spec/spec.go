package spec

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
)

// client packet segment format
// connId close network addrType addr   segment
// [4]    [1]   [1]     [1]      [18]   [x]
//
// server packet segment format
// connId close segment
// [4]    [1]   [x]

// Tohc the toh client
type Tohc interface {
	Dial(ctx context.Context, addr net.Addr) (net.Conn, error)
}

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
