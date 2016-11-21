FROM buildpack-deps

RUN hg clone https://hg.mozilla.org/projects/nspr
RUN hg clone https://hg.mozilla.org/projects/nss

ENV USE_64=1 NSS_ENABLE_TLS_1_3=1
# Incremental build snapshot disabled as dependencies don't seem to be solid:
# the same value changed in a header file would apply to one .c file and not another
# RUN cd nss && make nss_build_all

# Draft 15
# ARG REVISION=c483e5f9e0bc

# Draft 16
# ARG REVISION=3e7b53b18112

# Draft 18
# ARG REVISION=b6dfef6d0ff0

# tstclnt resumption
ARG REVISION=460a0a1e009f

RUN cd nss && hg pull
RUN cd nss && hg checkout -C $REVISION

ADD *.patch ./
RUN for p in *.patch; do patch -p1 -d nss < $p; done

RUN cd nss && make nss_build_all

# ENV HOST=localhost
# RUN cd nss/tests/ssl_gtests && ./ssl_gtests.sh

RUN cd nss && make install

RUN mv /dist/$(uname -s)$(uname -r | cut -f 1-2 -d . -)_$(uname -m)_${CC:-cc}_glibc_PTH_64_$([ -n "$BUILD_OPT" ] && echo OPT || echo DBG).OBJ /dist/OBJ-PATH

ENV LD_LIBRARY_PATH=/dist/OBJ-PATH/lib

ENV SSLTRACE=100 SSLDEBUG=100

ADD httpreq.txt /httpreq.txt
ADD run.sh /run.sh
ENTRYPOINT ["/run.sh"]
