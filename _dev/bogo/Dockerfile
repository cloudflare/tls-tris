FROM golang:1.7-alpine

RUN apk add --update \
    git \
    make \
    bash \
  && rm -rf /var/cache/apk/*

ENV CGO_ENABLED=0

RUN git clone https://github.com/FiloSottile/crypto-tls-bogo-shim \
    /go/src/github.com/FiloSottile/crypto-tls-bogo-shim

# Draft 18 with client-tests branch
ARG REVISION=3f5e87d6a1931b6f6930e4eadb7b2d0b2aa7c588

RUN cd /go/src/github.com/FiloSottile/crypto-tls-bogo-shim && \
    git checkout $REVISION

WORKDIR /go/src/github.com/FiloSottile/crypto-tls-bogo-shim
CMD ["make", "run"]
