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
	if ws.buf != nil {
		n = copy(b, ws.buf)
		if n < len(ws.buf) {
			ws.buf = ws.buf[n:]
		} else {
			ws.buf = nil
		}
		return
	}

	_, wsb, err := ws.ws.Read(context.Background())
	if err != nil {
		return len(wsb), err
	}

	n = copy(b, wsb)
	if n < len(wsb) {
		ws.buf = wsb[n:]
	}
	return
}

func (ws *WSReadWrite) Write(p []byte) (n int, err error) {
	err = ws.ws.Write(context.Background(), websocket.MessageBinary, p)
	return len(p), err
}
