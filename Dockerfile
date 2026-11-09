# Build Geth in a stock Go builder container
FROM golang:1.26.10-alpine AS builder

RUN apk add --no-cache make gcc musl-dev linux-headers git

ADD . /go-ethereum
RUN cd /go-ethereum && make geth

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
# Run as an unprivileged user (uid 1000, like the ubuntu user on the hosts)
# so that bind-mounted host data dirs keep working. Default datadir is
# /home/geth/.ethereum; pass --datadir to use another mounted path.
RUN adduser -D -u 1000 -h /home/geth geth && \
    install -d -o geth -g geth /home/geth/.ethereum
COPY --from=builder /go-ethereum/build/bin/geth /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp 30304/udp
USER geth
WORKDIR /home/geth
ENTRYPOINT ["geth"]
