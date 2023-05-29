package server

import "net/http"

type Config struct {
	// maxmind geoip2 db path
	Geoip2 string `yaml:"geoip2"`
	// socks5+http proxy server listen addr
	Listen string `yaml:"listen"`
	// advertised server addr
	Advertise *Advertise `yaml:"advertise,omitempty"`
	// toh server list
	Servers []TohServer `yaml:"servers"`
	// group toh servers
	Groups []ServerGroup `yaml:"groups,omitempty"`
	// network direct access settings
	Direct *Direct `yaml:"direct,omitempty"`
}

// Advertise since the socks5 server can listen to multiple network cards or be reverse-proxyed
// we need to set an advertising ip and port
// for example, socks5 UDP ASSOCIATE refers to this address when responding to the client
type Advertise struct {
	IP   string `yaml:"ip,omitempty"`
	Port uint16 `yaml:"port,omitempty"`
}

type TohServer struct {
	// name to identify the toh server
	Name string `yaml:"name"`
	// toh server adderss. i.e. https://fill-in-your-server-here.toh.sh/ws
	Addr string `yaml:"addr"`
	// toh server authcate key
	Key string `yaml:"key"`
	// this server is used when the remote accessed by the user hits this ruleset
	Ruleset []string `yaml:"ruleset,omitempty"`
	// url that responds to any http status code. dual stack IP should be supported
	Healthcheck string `yaml:"healthcheck,omitempty"`
	// the interval send ping to the under websocket conn for keepalive
	Keepalive string `yaml:"keepalive,omitempty"`
	// customize the request header sent to the toh server
	Headers http.Header `yaml:"headers,omitempty"`
}

type ServerGroup struct {
	// name to identify the server group
	Name string `yaml:"name"`
	// toh server name list from `servers` section
	Servers []string `yaml:"servers"`
	// same as `servers` section
	Ruleset []string `yaml:"ruleset"`
}

type Direct struct {
	// url that responds to any http status code. dual stack IP should be supported
	Healthcheck string `yaml:"healthcheck,omitempty"`
}
