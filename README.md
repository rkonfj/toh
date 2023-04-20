# Introduction

`toh` is tcp over http. 

### Client
```
import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/rkonfj/toh/client"
)

func main() {
	c, err := client.NewTohClient(client.Options{
		ServerAddr: "wss://l4us.synf.in/ws",
		ApiKey:     "5868a941-3025-4c6d-ad3a-41e29bb42e5f",
	})
	if err != nil {
		panic(err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return c.DialTCP(ctx, addr)
			},
		},
	}

	resp, err := httpClient.Get("https://www.google.com")
	if err != nil {
		panic(err)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}
```

### Server
- Build
```sh
git clone https://github.com/rkonfj/toh.git
go build -ldflags "-s -w"
```

- Usage

**As nginx backend**
```
# ./toh --help
A tcp over http/ws server daemon

Usage:
  toh [flags]

Flags:
      --acl string         file path for authentication (default "acl.json")
  -h, --help               help for toh
  -l, --listen string      http server listen address (ip:port) (default "0.0.0.0:9986")
      --log-level string   logrus logger level (default "info")
# ./toh 
time="2023-04-20T02:39:45-04:00" level=info msg="acl: load 1 keys"
time="2023-04-20T02:39:45-04:00" level=info msg="server listen 0.0.0.0:9986 now"
```
**Nginx**
```
server {
	listen 443 ssl;
	server_name l4us.fnla.io;

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