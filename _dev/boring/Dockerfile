FROM alpine

RUN apk add --update \
    git \
    cmake \
    patch \
    perl \
    python \
    build-base \
    go \
    ninja \
  && rm -rf /var/cache/apk/*

RUN git clone https://boringssl.googlesource.com/boringssl

RUN mkdir boringssl/build

# Draft 14
# ARG REVISION=88536c3

# Draft 15
# RUN cd boringssl && git fetch https://boringssl.googlesource.com/boringssl refs/changes/40/10840/18:draft15
# ARG REVISION=cae930d

# Draft "14.25" (sigalg renumbering)
# ARG REVISION=af56fbd

# Draft "14.25" w/ x25519 only
# ARG REVISION=c8b6b4f

# Draft "14.5" (sigalg, x25519, version ext)
# ARG REVISION=54afdab

# Draft 16
# ARG REVISION=89917a5

# Draft 18
# ARG REVISION=9b885c5
# Draft 18, but with "bssl server -loop -www" support and build fix
# ARG REVISION=40b24c8154

# Draft 21
# ARG REVISION=cd8470f

# Draft 22
# ARG REVISION=1530ef3e

# Draft 23
# ARG REVISION=cb15cfda29c0c60d8d74145b17c93b43a7667837

# Draft 28
# ARG REVISION=861f384d7bc59241a9df1634ae938d8e75be2d30

# TLS 1.3
ARG REVISION=ff433815b51c34496bb6bea13e73e29e5c278238

ADD sidh_$REVISION.patch /

RUN cd boringssl && git fetch
RUN cd boringssl && git checkout $REVISION
RUN cd boringssl && patch -p1 < /sidh_$REVISION.patch
RUN cd boringssl/build && cmake -GNinja ..
RUN cd boringssl && ninja -C build

ADD httpreq.txt /httpreq.txt
ADD run.sh /run.sh
ADD server.sh rsa.pem ecdsa.pem /
ADD client_rsa.key client_rsa.crt client_ca.crt /
ENTRYPOINT ["/run.sh"]
