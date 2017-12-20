FROM golang:1.9-alpine

RUN apk add --update \
    git \
    make \
    bash \
    patch \
  && rm -rf /var/cache/apk/*

ENV CGO_ENABLED=0

RUN git clone https://github.com/FiloSottile/crypto-tls-bogo-shim \
    /go/src/github.com/FiloSottile/crypto-tls-bogo-shim

# Draft 18 with client-tests branch
#ARG REVISION=3f5e87d6a1931b6f6930e4eadb7b2d0b2aa7c588

# Draft 22 with draft22 branch
#ARG REVISION=81cc32b846c9fe2ea32613287e57a6a0db7bbb9a

# Draft 22 with draft22-client branch (client-tests + draft22)
ARG REVISION=f9729b5e4eafb1f1d313949388c3c2b167e84734

RUN cd /go/src/github.com/FiloSottile/crypto-tls-bogo-shim && \
    git checkout $REVISION

WORKDIR /go/src/github.com/FiloSottile/crypto-tls-bogo-shim
CMD ["make", "run"]
