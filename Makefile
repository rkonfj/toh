version ?= unknown
git_hash := $(shell git rev-parse --short HEAD)
gomod := github.com/rkonfj/toh

GOBUILD := CGO_ENABLED=0 go build -ldflags "-s -w -X '${gomod}/spec.Version=${version}' -X '${gomod}/spec.Commit=${git_hash}'"

all: linux darwin windows

linuxamd64:
	GOOS=linux GOARCH=amd64 ${GOBUILD} -o toh-${version}-linux-amd64
linuxarm64:
	GOOS=linux GOARCH=arm64 ${GOBUILD} -o toh-${version}-linux-arm64
linux: linuxamd64 linuxarm64
darwinamd64:
	GOOS=darwin GOARCH=amd64 ${GOBUILD} -o toh-${version}-darwin-amd64
darwinarm64:
	GOOS=darwin GOARCH=arm64 ${GOBUILD} -o toh-${version}-darwin-arm64
darwin: darwinamd64 darwinarm64
windows:
	GOOS=windows GOARCH=amd64 ${GOBUILD} -o toh-${version}-windows-amd64.exe
image:
	docker build . -t rkonfj/toh:${version} --build-arg version=${version} --build-arg githash=${git_hash} --build-arg gomod=${gomod}
dockerhub: image
	docker push rkonfj/toh:${version}
github: clean all
	git tag -d ${version} 2>/dev/null || true
	gh release delete ${version} -y --cleanup-tag 2>/dev/null || true
	gh release create ${version} --generate-notes --title "toh ${version}" toh-*
dist: github dockerhub
clean:
	rm toh* 2>/dev/null || true
	rm *.zip 2>/dev/null || true
