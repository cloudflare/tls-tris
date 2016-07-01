FROM debian

RUN apt-get update
RUN apt-get install --yes mercurial
RUN apt-get install --yes build-essential libz-dev

RUN hg clone https://hg.mozilla.org/projects/nspr
RUN hg clone https://hg.mozilla.org/projects/nss

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
