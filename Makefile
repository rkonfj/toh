version ?= unknown
git_hash:=$(shell git rev-parse --short HEAD)

all: linuxamd64 linuxarm64 windows

linuxamd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X 'main.Version=${version}' -X 'main.Commit=${git_hash}'" -o toh-${version}-linux-amd64
linuxarm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X 'main.Version=${version}' -X 'main.Commit=${git_hash}'" -o toh-${version}-linux-arm64
windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X 'main.Version=${version}' -X 'main.Commit=${git_hash}'" -o toh-${version}-windows-amd64.exe
