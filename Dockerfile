FROM golang:1.20-alpine AS builder
ADD . /toh
ENV GOPROXY https://goproxy.cn,direct
WORKDIR /toh
RUN go build -ldflags "-s -w"

FROM alpine:3.17
WORKDIR /root
COPY --from=builder /toh/toh /usr/bin/toh
ENTRYPOINT ["/usr/bin/toh"]
CMD ["server"]
