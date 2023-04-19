package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type TohClient struct {
	ws       *websocket.Conn
	options  TohClientOptions
	proxyMap *sync.Map
}

type TohClientOptions struct {
	ServerAddr string
	ApiKey     string
}

func NewTohClient(options TohClientOptions) (*TohClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t1 := time.Now()
	conn, _, err := websocket.Dial(ctx,
		fmt.Sprintf("%s?apiKey=%s", options.ServerAddr, options.ApiKey), nil)
	if err != nil {
		log.Fatal(err)
	}
	toh := &TohClient{
		ws:       conn,
		options:  options,
		proxyMap: &sync.Map{},
	}
	logrus.Info("toh established successfully, latency ", time.Since(t1))
	go toh.watchServer()
	return toh, nil
}

func (c *TohClient) Dial(addr net.Addr) (net.Conn, error) {
	conn := TcpConn{
		addr: addr,
		toh:  c,
		buf:  bytes.Buffer{},
		id:   string(spec.Uint32ToBytes(uuid.New().ID())),
		sig:  make(chan struct{}, 1024),
	}

	c.proxyMap.Store(conn.id, &conn)
	return &conn, nil
}

func (c *TohClient) sendPacketSegment(ctx context.Context, connId string, addr net.Addr, b []byte) error {
	var network, addrType byte
	if addr.Network() == "tcp" {
		network = 0x00
	} else {
		return errors.New("unsupport protocol")
	}

	if addr.(*net.TCPAddr).IP.To4() == nil {
		addrType = 0x01
	} else {
		addrType = 0x00
	}

	body := &bytes.Buffer{}
	body.Write([]byte(connId))
	body.Write([]byte{0x00, network, addrType})
	body.Write([]byte(addr.(*net.TCPAddr).IP.To16()))
	body.Write(spec.Uint16ToBytes(uint16(addr.(*net.TCPAddr).Port)))
	body.Write(b)
	b1 := body.Bytes()
	return c.ws.Write(ctx, websocket.MessageBinary, b1)
}

func (c *TohClient) closeConn(connId string) error {
	body := &bytes.Buffer{}
	body.WriteString(connId)
	body.Write([]byte{0x01, 0x00, 0x00})
	return c.ws.Write(context.Background(), websocket.MessageBinary, body.Bytes())
}

func (c *TohClient) getConn(connId string) (*TcpConn, error) {
	if c, ok := c.proxyMap.Load(connId); ok {
		if conn, ok := c.(*TcpConn); ok {
			return conn, nil
		}
		return nil, errors.New("not conn")
	}
	return nil, errors.New("connection closed")
}

func (c *TohClient) watchServer() {
	for {
		typ, b, err := c.ws.Read(context.Background())
		if err != nil {
			panic(err)
		}
		if typ != websocket.MessageBinary {
			panic("not support")
		}

		conn, err := c.getConn(string(b[:4]))
		if err != nil {
			panic(err)
		}

		if b[4:5][0] == 1 {
			conn.closed = true
			logrus.Debugf("received close connection(%s) command", hex.EncodeToString(b[:4]))
			conn.sig <- struct{}{}
			continue
		}

		conn.buf.Write(b[5:])
		conn.sig <- struct{}{}
	}
}

type TcpConn struct {
	toh           *TohClient
	sig           chan struct{}
	addr          net.Addr
	buf           bytes.Buffer
	id            string
	closed        bool
	deadline      *time.Time
	readDeadline  *time.Time
	writeDeadline *time.Time
}

// Read reads data from the connection.
// Read can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetReadDeadline.
func (c *TcpConn) Read(b []byte) (n int, err error) {
	ctx := context.Background()
	if c.readDeadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.readDeadline)
		ctx = _ctx
		defer cancel()
	} else if c.deadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.deadline)
		ctx = _ctx
		defer cancel()
	}
	n, err = c.buf.Read(b)
	if err == io.EOF {
		if c.closed {
			return
		}
		select {
		case <-c.sig:
		case <-ctx.Done():
		}
		return c.Read(b)
	}
	return
}

// Write writes data to the connection.
// Write can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetWriteDeadline.
func (c *TcpConn) Write(b []byte) (n int, err error) {
	ctx := context.Background()
	if c.writeDeadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.writeDeadline)
		ctx = _ctx
		defer cancel()
	} else if c.deadline != nil {
		_ctx, cancel := context.WithDeadline(context.Background(), *c.deadline)
		ctx = _ctx
		defer cancel()
	}
	err = c.toh.sendPacketSegment(ctx, c.id, c.addr, b)
	if err != nil {
		return
	}
	return len(b), nil
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *TcpConn) Close() error {
	close(c.sig)
	c.toh.closeConn(c.id)
	return nil
}

// LocalAddr returns the local network address, if known.
func (c *TcpConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the remote network address, if known.
func (c *TcpConn) RemoteAddr() net.Addr {
	return c.addr
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail instead of blocking. The deadline applies to all future
// and pending I/O, not just the immediately following call to
// Read or Write. After a deadline has been exceeded, the
// connection can be refreshed by setting a deadline in the future.
//
// If the deadline is exceeded a call to Read or Write or to other
// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
// The error's Timeout method will return true, but note that there
// are other possible errors for which the Timeout method will
// return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *TcpConn) SetDeadline(t time.Time) error {
	c.deadline = &t
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c *TcpConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = &t
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *TcpConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = &t
	return nil
}
