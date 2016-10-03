FROM alpine

RUN apk add --update \
    git \
    cmake \
    perl \
    python \
    build-base \
    go \
    ninja \
  && rm -rf /var/cache/apk/*

RUN git clone https://boringssl.googlesource.com/boringssl
RUN cd boringssl && git fetch https://boringssl.googlesource.com/boringssl refs/changes/40/10840/16:draft15

# see _dev/boring for REVISION info
ARG REVISION=54afdab

RUN cd boringssl && git fetch
RUN cd boringssl && git checkout $REVISION

ADD bogo-client.go /bogo-client.go
RUN go build /bogo-client.go

ADD run.sh /run.sh
ENTRYPOINT ["/run.sh"]
