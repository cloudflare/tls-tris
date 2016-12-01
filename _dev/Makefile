GO ?= go
GOENV := $(shell $(GO) env GOOS)_$(shell $(GO) env GOARCH)
GOROOTINFO := $(shell $(GO) version | cut -d' ' -f 3)_$(GOENV)

.PHONY: GOROOT
GOROOT: GOROOT/$(GOENV)/.ok_$(GOROOTINFO)
	@rm -f GOROOT/$(GOENV)/pkg/*/crypto/tls.a

GOROOT/$(GOENV)/.ok_$(GOROOTINFO):
	rm -rf GOROOT/$(GOENV)
	mkdir -p GOROOT/$(GOENV)/pkg
	cp -r "$(shell $(GO) env GOROOT)/src" GOROOT/$(GOENV)/src
	cp -r "$(shell $(GO) env GOROOT)/pkg/include" GOROOT/$(GOENV)/pkg/include
	cp -r "$(shell $(GO) env GOROOT)/pkg/tool" GOROOT/$(GOENV)/pkg/tool
	rm -r GOROOT/$(GOENV)/src/crypto/tls
	ln -s ../../../../.. GOROOT/$(GOENV)/src/crypto/tls
	GOROOT="$(CURDIR)/GOROOT/$(GOENV)" $(GO) install -v std
ifeq ($(shell go env CGO_ENABLED),1)
	GOROOT="$(CURDIR)/GOROOT/$(GOENV)" $(GO) install -race -v std
endif
	@touch "$@"

# Note: when changing this, if it doesn't change the Go version
# (it should), you need to run make clean.
GO_COMMIT := 112098da9940c40952a8ffe3730edf56e75018ec

.PHONY: go
go: go/.ok_$(GO_COMMIT)_$(GOENV)

go/.ok_$(GO_COMMIT)_$(GOENV):
	rm -rf go/.ok_*_$(GOENV) go/$(GOENV)
	mkdir -p go
	git clone --branch 1.7.3 --single-branch --depth 25 https://github.com/cloudflare/go go/$(GOENV)
	cd go/$(GOENV) && git checkout $(GO_COMMIT)
	cd go/$(GOENV)/src && GOROOT_BOOTSTRAP="$(shell $(GO) env GOROOT)" ./make.bash
	@touch "$@"

.PHONY: clean
clean:
	rm -rf GOROOT go
