# Client Library

**TCP**

```
package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"

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

	io.Copy(os.Stdout, resp.Body)
}

```