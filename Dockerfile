FROM golang:1.21-alpine AS builder
ADD . /toh
WORKDIR /toh
ARG version=unknown
ARG githash=unknown
ARG gomod=github.com/rkonfj/toh
RUN go build -ldflags "-s -w -X '$gomod/spec.Version=$version' -X '$gomod/spec.Commit=$githash'"

FROM alpine:3.17
WORKDIR /root
COPY --from=builder /toh/toh /usr/bin/toh
ENTRYPOINT ["/usr/bin/toh"]
CMD ["serve"]
