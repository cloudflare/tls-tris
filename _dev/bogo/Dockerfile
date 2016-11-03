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

# see _dev/boring for REVISION info
ARG REVISION=9b885c5

RUN cd boringssl && git fetch
RUN cd boringssl && git checkout $REVISION

ADD bogo-client.go /bogo-client.go
RUN go build /bogo-client.go

ADD run.sh /run.sh
ENTRYPOINT ["/run.sh"]
