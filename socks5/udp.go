package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/rkonfj/toh/spec"
	"github.com/sirupsen/logrus"
)

func (s *Socks5Server) startUDPListenLoop(l net.PacketConn) {
	buf := make([]byte, 16*1024)
	for {
		n, clientAddr, err := l.ReadFrom(buf)
		if err != nil {
			logrus.Error(err)
			break
		}

		go s.pipeSocks5UDP(buf[:n], l, clientAddr)
	}
}

func (s *Socks5Server) pipeSocks5UDP(packet []byte, udpConn net.PacketConn, clientAddr net.Addr) {
	addr, payload, err := decodeSocks5Packet(packet)
	if err != nil {
		logrus.Error(err)
		return
	}

	ctx := context.WithValue(context.Background(), spec.AppAddr, clientAddr.String())
	dialerName, conn, err := s.opts.UDPDialContext(ctx, addr)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(payload)
	if err != nil {
		logrus.Error(err)
		return
	}

	buf := make([]byte, 16*1024)
	n, err := conn.Read(buf)
	if err != nil {
		logrus.Error(err)
		return
	}

	udpPacket := bytes.Join([][]byte{
		{0, 0, 0, 1},
		net.ParseIP(s.opts.AdvertiseIP).To4(),
		spec.Uint16ToBytes(s.opts.AdvertisePort),
		buf[:n]}, []byte{})
	_, err = udpConn.WriteTo(udpPacket, clientAddr)
	if err != nil {
		logrus.Error(err)
		return
	}

	s.trafficEventChan <- &TrafficEvent{
		DialerName: dialerName,
		Network:    "udp",
		LocalAddr:  clientAddr.String(),
		RemoteAddr: addr,
		In:         int64(len(payload)),
		Out:        int64(n),
	}
}

func decodeSocks5Packet(packet []byte) (addr string, payload []byte, err error) {
	errInvalidDatagram := errors.New("invalid socks5 udp datagram")
	if len(packet) < 4 {
		err = errInvalidDatagram
		return
	}

	if packet[0] != 0 || packet[1] != 0 {
		err = errors.New("invalid socks5 udp datagram (RSV)")
		return
	}

	if packet[2] != 0 {
		err = errors.New("discard fragmented payload")
		return
	}

	switch packet[3] {
	case 1:
		if len(packet) < 4+4+2 {
			err = errInvalidDatagram
			return
		}
		host := net.IPv4(packet[4], packet[5], packet[6], packet[7]).String()
		port := spec.BytesToUint16(packet[8 : 8+2])
		addr = fmt.Sprintf("%s:%d", host, port)
		payload = packet[4+4+2:]
	case 3:
		if len(packet) < 4+1 {
			err = errInvalidDatagram
			return
		}
		if len(packet) < 4+int(packet[4])+2 {
			err = errInvalidDatagram
			return
		}
		host := string(packet[5 : 5+packet[4]])
		port := spec.BytesToUint16(packet[5+packet[4] : 5+packet[4]+2])
		addr = fmt.Sprintf("%s:%d", host, port)
		payload = packet[4+int(packet[4])+2:]
	default:
		err = errors.New("discard unsupport ATYP")
		return
	}
	return
}
