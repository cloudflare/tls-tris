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
RUN mkdir boringssl/build
RUN cd boringssl/build && cmake -GNinja ..
RUN cd boringssl && ninja -C build

# Draft 14
#ARG REVISION=88536c3

# Draft 15
RUN cd boringssl && git fetch https://boringssl.googlesource.com/boringssl refs/changes/45/8745/31
ARG REVISION=e3092d2

RUN cd boringssl && git fetch
RUN cd boringssl && git checkout $REVISION
RUN cd boringssl/build && cmake -GNinja ..
RUN cd boringssl && ninja -C build

ADD run.sh /run.sh
ENTRYPOINT ["/run.sh"]
