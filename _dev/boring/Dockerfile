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

# Cacheable layer of compilation, to make the next incremental
RUN cd boringssl && git checkout 9b885c5
RUN mkdir boringssl/build
RUN cd boringssl/build && cmake -GNinja ..
RUN cd boringssl && ninja -C build

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
ARG REVISION=9b885c5

RUN cd boringssl && git fetch
RUN cd boringssl && git checkout $REVISION
RUN cd boringssl/build && cmake -GNinja ..
RUN cd boringssl && ninja -C build

ADD httpreq.txt /httpreq.txt
ADD run.sh /run.sh
ENTRYPOINT ["/run.sh"]
