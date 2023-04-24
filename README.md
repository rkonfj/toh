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
time="2023-04-20T02:39:45-04:00" level=info msg="acl: load 1 keys"
time="2023-04-20T02:39:45-04:00" level=info msg="server listen 0.0.0.0:9986 now"
```
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
**Buildin port-forward tool `pf` act as client**

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
INFO[2023-04-24T09:43:32+08:00] socks5 listen on 0.0.0.0:2080 now
INFO[2023-04-24T09:43:32+08:00] udp://8.8.8.8:53 established successfully, toh latency 753.098828ms
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

# https_proxy=socks5://127.0.0.1:2080 curl -i https://www.google.com/generate_204
HTTP/2 204
cross-origin-resource-policy: cross-origin
date: Mon, 24 Apr 2023 01:47:57 GMT
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
```
