# Introduction

`toh` is tcp over http. 

### Client
```
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/rkonfj/toh/client"
)

func main() {
	c, err := client.NewTohClient(client.Options{
		ServerAddr: "ws://172.25.53.251:9986",
		ApiKey:     "aafc1828-09f4-4c1a-9607-f096d27caae9",
	})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := c.DialTCP(ctx, "172.18.20.6:80")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: 172.18.20.6\r\nConnection: close\r\n\r\n"))

	response := bytes.Buffer{}
	buf := make([]byte, 512)
	for {
		n, err := conn.Read(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
		response.Write(buf[:n])
	}
	fmt.Println(response.String())
}
```

### Server
- Build
```sh
git clone https://github.com/rkonfj/toh.git
go build -ldflags "-s -w"
```

- Usage
```
./toh --help
A tcp over http/ws server daemon

Usage:
  toh [flags]

Flags:
      --acl string         file path for authentication (default "acl.json")
  -h, --help               help for toh
  -l, --listen string      http server listen address (ip:port) (default "0.0.0.0:9986")
      --log-level string   logrus logger level (default "info")
  -r, --read-buffer int    remote conn read buffer size (default 4096)
```