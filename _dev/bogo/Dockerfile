FROM golang:1.7-alpine

RUN apk add --update \
    git \
    make \
    bash \
  && rm -rf /var/cache/apk/*

ENV CGO_ENABLED=0

RUN   go get -d github.com/Lekensteyn/crypto-tls-bogo-shim
WORKDIR /go/src/github.com/Lekensteyn/crypto-tls-bogo-shim
CMD ["make", "run"]
