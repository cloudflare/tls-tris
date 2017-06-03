# docker build -t tls-tris:testdata _dev/testdata
# GOOS=linux ./_dev/go.sh test -c crypto/tls
# docker run -it --rm -v "$(pwd):$(pwd)" -w "$(pwd)" tls-tris:testdata 
# ./tls.test -update -test.v -test.run SCTs
## === RUN   TestHandshakClientSCTs
## Wrote testdata/Client-TLSv12-SCT
## --- PASS: TestHandshakClientSCTs (0.62s)
## PASS

FROM alpine

RUN apk add --update \
		wget \
		build-base \
		perl \
		ca-certificates \
		linux-headers \
	&& rm -rf /var/cache/apk/*

RUN wget https://www.openssl.org/source/openssl-1.1.0c.tar.gz
RUN tar xvf openssl-1.1.0c.tar.gz
RUN cd openssl-1.1.0c && perl ./Configure enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method -static linux-x86_64
RUN cd openssl-1.1.0c && make
RUN cd openssl-1.1.0c && make install

ENTRYPOINT ["/bin/sh"]
