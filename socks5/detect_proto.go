package socks5

import "net"

type protoDetectionConnWrapper struct {
	net.Conn
	detectBytes []byte
}

func (c *protoDetectionConnWrapper) Read(b []byte) (n int, err error) {
	if c.detectBytes != nil {
		n = copy(b, c.detectBytes)
		if n < len(c.detectBytes) {
			c.detectBytes = c.detectBytes[n:]
		} else {
			c.detectBytes = nil
		}
		return
	}
	return c.Conn.Read(b)
}
