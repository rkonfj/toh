package server

import (
	"context"

	"nhooyr.io/websocket"
)

type WSReadWrite struct {
	ws  *websocket.Conn
	buf []byte
}

func RWWS(ws *websocket.Conn) *WSReadWrite {
	return &WSReadWrite{ws: ws}
}

func (ws *WSReadWrite) Read(b []byte) (n int, err error) {
	if len(ws.buf) > 0 {
		if len(ws.buf) <= len(b) {
			copy(b, ws.buf)
			ws.buf = nil
			return len(ws.buf), nil
		}
		copy(b, ws.buf[:len(b)])
		ws.buf = ws.buf[len(b):]
		return len(b), nil
	}

	_, wsb, err := ws.ws.Read(context.Background())
	if err != nil {
		return len(wsb), err
	}

	if len(wsb) > len(b) {
		copy(b, wsb[:len(b)])
		ws.buf = make([]byte, len(wsb[len(b):]))
		copy(ws.buf, wsb[len(b):])
		return len(b), nil
	}
	copy(b, wsb)
	return len(wsb), nil
}

func (ws *WSReadWrite) Write(p []byte) (n int, err error) {
	err = ws.ws.Write(context.Background(), websocket.MessageBinary, p)
	return len(p), err
}
