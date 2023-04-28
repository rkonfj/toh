version ?= unknown
git_hash := $(shell git rev-parse --short HEAD)
gomod := github.com/rkonfj/toh

all: linuxamd64 linuxarm64 windows winsw

linuxamd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X '${gomod}/spec.Version=${version}' -X '${gomod}/spec.Commit=${git_hash}'" -o toh-${version}-linux-amd64
linuxarm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X '${gomod}/spec.Version=${version}' -X '${gomod}/spec.Commit=${git_hash}'" -o toh-${version}-linux-arm64
windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X '${gomod}/spec.Version=${version}' -X '${gomod}/spec.Commit=${git_hash}'" -o toh-${version}-windows-amd64.exe
winsw: windows
	curl -L -o dist/socks5toh/socks5toh.exe https://github.com/winsw/winsw/releases/latest/download/WinSW-x64.exe
	cp toh-${version}-windows-amd64.exe dist/socks5toh/toh.exe
	zip -rj socks5toh-${version}-winsw-amd64.zip dist/socks5toh 