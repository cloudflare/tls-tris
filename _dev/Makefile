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

GO_COMMIT := 0101ee6a26adbec874a4253dc90bdd049e403e57

.PHONY: go
go: .ok_go_$(GO_COMMIT)_$(GOENV)

.ok_go_$(GO_COMMIT)_$(shell $(GO) env GOOS)_$(shell $(GO) env GOARCH):
	rm -rf go_$(GOENV)
	git clone --branch 1.7 --single-branch --depth 25 https://github.com/cloudflare/go go_$(GOENV)
	cd go_$(GOENV) && git checkout $(GO_COMMIT)
	cd go_$(GOENV)/src && GOROOT_BOOTSTRAP="$(shell $(GO) env GOROOT)" ./make.bash
	@touch "$@"

.PHONY: clean
clean:
	rm -rf GOROOT go_* .ok_go_*
