all: bin/tris-publicserver bin/tris-localserver

GO ?= go
GOROOTINFO := $(shell $(GO) version | cut -d' ' -f 3)_$(shell $(GO) env GOOS)_$(shell $(GO) env GOARCH)

.PHONY: GOROOT
GOROOT: GOROOT/.ok_$(GOROOTINFO)
	@rm -f GOROOT/pkg/*/crypto/tls.a

GOROOT/.ok_$(GOROOTINFO):
	rm -rf GOROOT
	mkdir -p GOROOT/pkg
	cp -r "$(shell $(GO) env GOROOT)/src" GOROOT/src
	cp -r "$(shell $(GO) env GOROOT)/pkg/include" GOROOT/pkg/include
	cp -r "$(shell $(GO) env GOROOT)/pkg/tool" GOROOT/pkg/tool
	rm -r GOROOT/src/crypto/tls
	ln -s ../../../.. GOROOT/src/crypto/tls
	@touch "$@"
