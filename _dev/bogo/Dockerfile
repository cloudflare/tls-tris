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

# Draft 14
# ARG REVISION=88536c3

# Draft 15
# RUN cd boringssl && git fetch https://boringssl.googlesource.com/boringssl refs/changes/45/8745/31
# ARG REVISION=e3092d2

# Draft 14.25 (sigalg renumbering)
ARG REVISION=af56fbd

RUN cd boringssl && git fetch
RUN cd boringssl && git checkout $REVISION

ADD bogo-client.go /bogo-client.go
RUN go build /bogo-client.go

ADD run.sh /run.sh
ENTRYPOINT ["/run.sh"]
