all: bin/tris-publicserver bin/tris-localserver

.PHONY: GOROOT
GOROOT: GOROOT/.ok
	@rm -f GOROOT/pkg/*/crypto/tls.a

GOROOT/.ok:
	rm -rf GOROOT
	mkdir -p GOROOT/pkg
	cp -r "$(shell go env GOROOT)/src" GOROOT/src
	cp -r "$(shell go env GOROOT)/pkg/include" GOROOT/pkg/include
	cp -r "$(shell go env GOROOT)/pkg/tool" GOROOT/pkg/tool
	rm -r GOROOT/src/crypto/tls
	ln -s ../../../.. GOROOT/src/crypto/tls
	@touch "$@"

bin:
	mkdir -p "$@"

bin/tris-publicserver: bin tris-publicserver/* ../*.go GOROOT
	GOROOT="$(CURDIR)/GOROOT" go build -i -v -o "$@" ./tris-publicserver
bin/tris-localserver: bin tris-localserver/* ../*.go GOROOT
	GOROOT="$(CURDIR)/GOROOT" go build -i -v -o "$@" ./tris-localserver
