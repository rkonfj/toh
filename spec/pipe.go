package spec

import (
	"io"
	"net"
	"sync"
)

type TrafficEvent struct {
	DialerName, Network, RemoteAddr, LocalAddr string
	In, Out                                    int64
}

type TrafficEventConsumer func(e *TrafficEvent)

type PipeEngine struct {
	consumer  TrafficEventConsumer
	eventChan chan *TrafficEvent
}

func NewPipeEngine() *PipeEngine {
	return &PipeEngine{
		eventChan: make(chan *TrafficEvent, 4096),
	}
}

func (s *PipeEngine) SetTrafficEventConsumer(c TrafficEventConsumer) {
	s.consumer = c
}

func (s *PipeEngine) PubEvent(e *TrafficEvent) {
	s.eventChan <- e
}

func (s *PipeEngine) RunTrafficEventConsumeLoop() {
	for e := range s.eventChan {
		if s.consumer != nil {
			s.consumer(e)
			continue
		}
	}
}

func (s *PipeEngine) Pipe(dialerName string, conn, rConn net.Conn) {
	if conn == nil || rConn == nil {
		return
	}
	var lbc, rbc int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rbc, _ = io.Copy(conn, rConn)
		conn.Close()
	}()
	lbc, _ = io.Copy(rConn, conn)
	rConn.Close()
	wg.Wait()
	s.eventChan <- &TrafficEvent{
		DialerName: dialerName,
		Network:    "tcp",
		LocalAddr:  conn.RemoteAddr().String(),
		RemoteAddr: rConn.RemoteAddr().String(),
		In:         lbc,
		Out:        rbc,
	}
}
