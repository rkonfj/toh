package socks5

type TrafficEvent struct {
	DialerName, Network, RemoteAddr, LocalAddr string
	In, Out                                    int64
}

type TrafficEventConsumer func(e *TrafficEvent)

func (s *Socks5Server) SetTrafficEventConsumer(c TrafficEventConsumer) {
	s.opts.TrafficEventConsumer = c
}

func (s *Socks5Server) startTrafficEventConsumeLoop() {
	go func() {
		for e := range s.trafficEventChan {
			if s.opts.TrafficEventConsumer != nil {
				s.opts.TrafficEventConsumer(e)
				continue
			}
		}
	}()
}
