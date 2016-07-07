FROM debian

# docker run -i tstclnt -D -V tls1.3:tls1.3 -o -O -h $(docker inspect tris-localserver | jq -r '.[0].NetworkSettings.IPAddress') -p 443

RUN apt-get update
RUN apt-get install --yes mercurial
RUN apt-get install --yes build-essential libz-dev

ARG REVISION=default
RUN hg clone https://hg.mozilla.org/projects/nspr
RUN hg clone https://hg.mozilla.org/projects/nss
RUN cd nss && hg checkout -C $REVISION

ADD *.patch ./
RUN for p in *.patch; do patch -p1 -d nss < $p; done

ENV USE_64=1 NSS_ENABLE_TLS_1_3=1
RUN cd nss && make nss_build_all

ENV HOST=localhost
RUN cd nss/tests/ssl_gtests && ./ssl_gtests.sh

RUN cd nss && make install
RUN mv /dist/$(uname -s)$(uname -r | cut -f 1-2 -d . -)_$(uname -m)_${CC:-cc}_glibc_PTH_64_$([ -n "$BUILD_OPT" ] && echo OPT || echo DBG).OBJ /dist/OBJ-PATH
ENV LD_LIBRARY_PATH=/dist/OBJ-PATH/lib
ENV SSLTRACE=100 SSLDEBUG=100
ENTRYPOINT ["/dist/OBJ-PATH/bin/tstclnt"]
CMD ["-D", "-V", "tls1.3:tls1.3", "-o", "-O", "-h", "192.168.64.1", "-p", "4433"]
