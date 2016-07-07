all: bin/tris-publicserver bin/tris-localserver

GOROOTINFO := $(shell go version | cut -d' ' -f 3)_$(shell go env GOOS)_$(shell go env GOARCH)

.PHONY: GOROOT
GOROOT: GOROOT/.ok_$(GOROOTINFO)
	@rm -f GOROOT/pkg/*/crypto/tls.a

GOROOT/.ok_$(GOROOTINFO):
	rm -rf GOROOT
	mkdir -p GOROOT/pkg
	cp -r "$(shell go env GOROOT)/src" GOROOT/src
	cp -r "$(shell go env GOROOT)/pkg/include" GOROOT/pkg/include
	cp -r "$(shell go env GOROOT)/pkg/tool" GOROOT/pkg/tool
	rm -r GOROOT/src/crypto/tls
	ln -s ../../../.. GOROOT/src/crypto/tls
	@touch "$@"
