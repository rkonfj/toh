# Introduction

`toh` is tcp over http. 

for example:
```
c, err := client.NewTohClient(client.TohClientOptions{
    ServerAddr: "ws://192.168.3.98:9986",
    ApiKey:     "74c1e17f-4352-4fe3-8c27-f024bf8bcde8",
})
if err != nil {
    panic(err)
}

addr := netip.MustParseAddrPort("192.168.3.79:80")
ip := addr.Addr().As4()

conn, err := c.Dial(context.Background(), &net.TCPAddr{IP: ip[:], Port: int(addr.Port())})
if err != nil {
    panic(err)
}
defer conn.Close()

conn.Write([]byte("GET / HTTP/1.1\r\nHost: 192.168.3.79\r\nConnection: close\r\n\r\n"))

response := bytes.Buffer{}
buf := make([]byte, 1024)
for {
    n, err := conn.Read(buf)
    if err == io.EOF {
        break
    }
    response.Write(buf[:n])
}
fmt.Println("resp:", response.String())
```