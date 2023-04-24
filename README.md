# Introduction

`toh` is tcp over http. short words: proxy your network over websocket

**ToH server as nginx backend**
- Build
```
# git clone https://github.com/rkonfj/toh.git
# go build -ldflags "-s -w"
```

- Run
```
# ./toh server --help
Server daemon

Usage:
  toh [flags]

Flags:
      --acl string         file path for authentication (default "acl.json")
  -h, --help               help for toh
  -l, --listen string      http server listen address (ip:port) (default "0.0.0.0:9986")
      --log-level string   logrus logger level (default "info")
# ./toh server
INFO[2023-04-24T19:35:12+08:00] initializing ack file acl.json               
{
    "keys": [
        {
            "name": "default",
            "key": "8bed5424-5058-434d-b1d7-ba7db0d780af"
        }
    ]
}
INFO[2023-04-24T19:35:12+08:00] acl: load 1 keys                             
INFO[2023-04-24T19:35:12+08:00] server listen 0.0.0.0:9986 now
```
the `key` here will used by `pf` or `socks5`

**Nginx**
```
server {
	listen 443 ssl;
	server_name l4us.synf.in;

	ssl_certificate     tls.crt;
	ssl_certificate_key tls.key;

	location /ws {
		proxy_pass http://127.0.0.1:9986;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection upgrade;
	}
}
```
**Buildin port-forward tool `pf` act as ToH client**

```
# ./toh pf --help
Client for port-forwarding

Usage:
  toh pf [flags]

Flags:
  -k, --api-key string    the ToH api-key for authcate
  -f, --forward strings   tunnel mapping (<net>/<local>/<remote>, ie: udp/0.0.0.0:53/8.8.8.8:53)
  -h, --help              help for pf
  -s, --server string     the ToH server address
      --socks5 string     socks5 server (default "0.0.0.0:2080")

# ./toh pf -s wss://l4us.synf.in/ws -k 5868a941-3025-4c6d-ad3a-41e29bb42e5f -f udp/127.0.0.53:53/8.8.8.8:53 -f tcp/0.0.0.0:1080/google.com:80
INFO[2023-04-24T09:47:13+08:00] listen udp://127.0.0.53:53 for 8.8.8.8:53 now
INFO[2023-04-24T09:43:32+08:00] listen tcp://0.0.0.0:1080 for google.com:80 now
```

another shell
```
# dig @127.0.0.53 www.google.com +short
142.250.68.4

# curl 127.0.0.1:8080
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com:8080/">here</A>.
</BODY></HTML>
```

**Buildin socks5 proxy server act as ToH client**
```
# ./toh socks5 --help
Socks5 proxy server

Usage:
  toh socks5 [flags]

Flags:
  -c, --config string   socks5 server config file (default is $HOME/.config/toh/socks5.yml)
  -h, --help            help for socks5

Global Flags:
      --log-level string   logrus logger level (default "info")
# ./toh socks5
INFO[2023-04-24T19:44:25+08:00] initializing config file /home/rkonfj/.config/toh/socks5.yml 
listen: 0.0.0.0:2080
servers:
  - name: us1
    api: wss://us-l4-vultr.synf.in/ws
    key: 5868a941-3025-4c6d-ad3a-41e29bb42e5f
    ruleset: https://file.synf.in/toh/rules/default.txt
INFO[2023-04-24T19:44:25+08:00] downloading https://file.synf.in/toh/rules/default.txt for us1 ruleset 
INFO[2023-04-24T19:44:25+08:00] ruleset us1: special 0, direct 0, wildcard 5 
INFO[2023-04-24T19:44:25+08:00] listen on 0.0.0.0:2080 for socks5 now
```

the server `us1` is the test server, will stopped in the future

another shell
```
# https_proxy=socks5://127.0.0.1:2080 curl -i https://www.google.com/generate_204
HTTP/2 204
cross-origin-resource-policy: cross-origin
date: Mon, 24 Apr 2023 01:47:57 GMT
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
```
