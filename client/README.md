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
		Server: "wss://fill-in-your-server-here.toh.sh/ws",
		Key:    "5CCQAoN905PdIejsal55Am3z2mXY6ueLrtdSA8OCpVc",
	})
	if err != nil {
		panic(err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: c.DialContext},
	}

	resp, err := httpClient.Get("https://api64.ipify.org")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)
}

```
**UDP**

```
package main

import (
	"context"
	"fmt"
	"net"

	"github.com/rkonfj/toh/client"
)

func main() {
	c, err := client.NewTohClient(client.Options{
		Server: "https://fill-in-your-server-here.toh.sh",
		Key:    "5CCQAoN905PdIejsal55Am3z2mXY6ueLrtdSA8OCpVc",
	})
	if err != nil {
		panic(err)
	}

	resolver := net.Resolver{
		PreferGo: true,
		Dial:     c.DialContext,
	}

	ips, err := resolver.LookupIP(context.Background(), "ip", "www.google.com")
	if err != nil {
		panic(err)
	}
	fmt.Println(ips)
}
```