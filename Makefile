version ?= unknown
git_hash := $(shell git rev-parse --short HEAD)
gomod := github.com/rkonfj/toh

LDFLAGS := -ldflags "-s -w -X '${gomod}/spec.Version=${version}' -X '${gomod}/spec.Commit=${git_hash}'"
ANDROID_CC_BIN := CC=${ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin

all: linux darwin windows

linuxamd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o toh-${version}-linux-amd64
linuxarm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ${LDFLAGS}	-o toh-${version}-linux-arm64
linux: linuxamd64 linuxarm64
darwinamd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o toh-${version}-darwin-amd64
darwinarm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o toh-${version}-darwin-arm64
darwin: darwinamd64 darwinarm64
windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o toh-${version}-windows-amd64.exe
image:
	docker build . -t rkonfj/toh:${version} --build-arg version=${version} --build-arg githash=${git_hash} --build-arg gomod=${gomod}
dockerhub: image
	docker push rkonfj/toh:${version}

github: clean all
	gh release create ${version} --generate-notes --title "toh ${version}" toh-*
dist: github dockerhub
clean:
	rm toh* 2>/dev/null || true
	rm *.zip 2>/dev/null || true
