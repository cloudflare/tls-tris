GO ?= go
GOENV := $(shell $(GO) env GOHOSTOS)_$(shell $(GO) env GOHOSTARCH)
GOROOTINFO := $(shell $(GO) version | cut -d' ' -f 3)_$(GOENV)

.PHONY: GOROOT
GOROOT: GOROOT/$(GOENV)/.ok_$(GOROOTINFO)
	@rm -f GOROOT/$(GOENV)/pkg/*/crypto/tls.a

GOROOT/$(GOENV)/.ok_$(GOROOTINFO):
	$(eval GOROOT := $(CURDIR)/GOROOT/$(GOENV))
	rm -rf "$(GOROOT)"
	mkdir -p "$(GOROOT)/pkg"
	cp -r "$(shell $(GO) env GOROOT)/src" "$(GOROOT)/src"
	cp -r "$(shell $(GO) env GOROOT)/pkg/include" "$(GOROOT)/pkg/include"
	cp -r "$(shell $(GO) env GOROOT)/pkg/tool" "$(GOROOT)/pkg/tool"
	rm -r "$(GOROOT)/src/crypto/tls"
	ln -s ../../../../.. "$(GOROOT)/src/crypto/tls"
	for p in $(wildcard $(CURDIR)/patches/*); do patch -d "$(GOROOT)" -p1 < "$$p"; done
	GOROOT="$(GOROOT)" $(GO) install -v std
ifeq ($(shell go env CGO_ENABLED),1)
	GOROOT="$(GOROOT)" $(GO) install -race -v std
endif
	@touch "$@"

.PHONY: clean
clean:
	rm -rf GOROOT go
