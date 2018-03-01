# Constants
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH))/..)
DEV_DIR      = $(PRJ_DIR)/_dev
# Results will be produced in this directory (can be provided by a caller)
BUILD_DIR   ?= $(PRJ_DIR)/_dev/GOROOT

# Compiler
GO ?= go

# Build environment
OS          ?= $(shell $(GO) env GOHOSTOS)
ARCH        ?= $(shell $(GO) env GOHOSTARCH)
OS_ARCH     := $(OS)_$(ARCH)
VER_OS_ARCH := $(shell $(GO) version | cut -d' ' -f 3)_$(OS)_$(ARCH)
GOROOT_ENV  := $(shell $(GO) env GOROOT)
GOROOT_LOCAL = $(BUILD_DIR)/$(OS_ARCH)
# Flag indicates wheter invoke "go install -race std". Supported only on amd64 with CGO enabled
INSTALL_RACE:= $(words $(filter $(ARCH)_$(shell go env CGO_ENABLED), amd64_1))

# TODO: I'm not sure why we would remove it at the end
#       but I comment this code as tls.a is exactly what
#       I try to build here
#GOROOT: GOROOT/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
#	rm -f GOROOT/$(OS_ARCH)/pkg/*/crypto/tls.a

$(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH): clean

# Create clean directory structure
	mkdir -p "$(GOROOT_LOCAL)/pkg"

# Copy src/tools from system GOROOT
	cp -r $(GOROOT_ENV)/src $(GOROOT_LOCAL)/src
	cp -r $(GOROOT_ENV)/pkg/include $(GOROOT_LOCAL)/pkg/include
	cp -r $(GOROOT_ENV)/pkg/tool $(GOROOT_LOCAL)/pkg/tool

# Swap TLS implementation
	rm -r $(GOROOT_LOCAL)/src/crypto/tls/*
	rsync -a $(PRJ_DIR)/ $(GOROOT_LOCAL)/src/crypto/tls/ --exclude=$(lastword $(subst /, ,$(DEV_DIR)))

# Apply additional patches
	for p in $(wildcard $(DEV_DIR)/patches/*); do patch -d "$(GOROOT_LOCAL)" -p1 < "$$p"; done

# Create go package
	GOARCH=$(ARCH) GOROOT="$(GOROOT_LOCAL)" $(GO) install -v std
ifeq ($(INSTALL_RACE),1)
	GOARCH=$(ARCH) GOROOT="$(GOROOT_LOCAL)" $(GO) install -race -v std
endif
	@touch "$@"

clean:
	rm -rf $(BUILD_DIR)/$(OS_ARCH)

clean-all:
	rm -rf $(BUILD_DIR)

# PHONY targets
.PHONY: $(BUILD_DIR) clean
