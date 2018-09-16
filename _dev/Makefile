# Constants
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH))/..)
DEV_DIR      = $(PRJ_DIR)/_dev
# Results will be produced in this directory (can be provided by a caller)
BUILD_DIR   ?= $(PRJ_DIR)/_dev/GOROOT

# Compiler
GO ?= go
DOCKER ?= docker

# Build environment
OS          ?= $(shell $(GO) env GOHOSTOS)
ARCH        ?= $(shell $(GO) env GOHOSTARCH)
OS_ARCH     := $(OS)_$(ARCH)
VER_OS_ARCH := $(shell $(GO) version | cut -d' ' -f 3)_$(OS)_$(ARCH)
GOROOT_ENV  := $(shell $(GO) env GOROOT)
GOROOT_LOCAL = $(BUILD_DIR)/$(OS_ARCH)
# Flag indicates wheter invoke "go install -race std". Supported only on amd64 with CGO enabled
INSTALL_RACE:= $(words $(filter $(ARCH)_$(shell go env CGO_ENABLED), amd64_1))

# Test targets used for compatibility testing
TARGET_TEST_COMPAT=boring picotls tstclnt

# Some target-specific constants
BORINGSSL_REVISION=d451453067cd665a5c38830fbbaac9e599234a5e
BOGO_DOCKER_TRIS_LOCATION=/go/src/github.com/cloudflare/tls-tris

###############
#
# Build targets
#
##############################
$(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH): clean

# Create clean directory structure
	mkdir -p "$(GOROOT_LOCAL)/pkg"

# Copy src/tools from system GOROOT
	cp -Hr $(GOROOT_ENV)/src $(GOROOT_LOCAL)/src
	cp -Hr $(GOROOT_ENV)/pkg/include $(GOROOT_LOCAL)/pkg/include
	cp -Hr $(GOROOT_ENV)/pkg/tool $(GOROOT_LOCAL)/pkg/tool

# Swap TLS implementation
	rm -r $(GOROOT_LOCAL)/src/crypto/tls/*
	rsync -rltgoD $(PRJ_DIR)/ $(GOROOT_LOCAL)/src/crypto/tls/ --exclude=$(lastword $(subst /, ,$(DEV_DIR)))

# Apply additional patches
	for p in $(wildcard $(DEV_DIR)/patches/*); do patch -d "$(GOROOT_LOCAL)" -p1 < "$$p"; done

# Create go package
	GOARCH=$(ARCH) GOROOT="$(GOROOT_LOCAL)" $(GO) install -v std
ifeq ($(INSTALL_RACE),1)
	GOARCH=$(ARCH) GOROOT="$(GOROOT_LOCAL)" $(GO) install -race -v std
endif
	@touch "$@"

build-test-%: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
	$(DOCKER) build $(BUILDARG) -t tls-tris:$* $(DEV_DIR)/$*
	$(DOCKER) build $(BUILDARG) -t $(*)-localserver $(DEV_DIR)/$*

build-all: \
	build-test-tris-client \
	build-test-tris-server \
	build-test-bogo \
	$(addprefix build-test-,$(TARGET_TEST_COMPAT))

# Builds TRIS client
build-test-tris-client: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
	cd $(DEV_DIR)/tris-testclient; CGO_ENABLED=0 GOROOT="$(GOROOT_LOCAL)" $(GO) build -v -i .
	$(DOCKER) build -t tris-testclient $(DEV_DIR)/tris-testclient

# Builds TRIS server
build-test-tris-server: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
	cd $(DEV_DIR)/tris-localserver; CGO_ENABLED=0 GOROOT="$(GOROOT_LOCAL)" $(GO) build -v -i .
	$(DOCKER) build -t tris-localserver $(DEV_DIR)/tris-localserver

# BoringSSL specific stuff
build-test-boring: 	BUILDARG=--build-arg REVISION=$(BORINGSSL_REVISION)

# TODO: This probably doesn't work
build-caddy: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
	CGO_ENABLED=0 GOROOT="$(GOROOT_LOCAL)" $(GO) build github.com/mholt/caddy

###############
#
# Test targets
#
##############################
test: \
	test-unit \
	test-bogo \
	test-interop

test-unit: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
	GOROOT="$(GOROOT_LOCAL)" $(GO) test -race crypto/tls

test-bogo:
	$(DOCKER) run --rm -v $(PRJ_DIR):$(BOGO_DOCKER_TRIS_LOCATION) tls-tris:bogo

test-interop:
	$(DEV_DIR)/interop_test_runner -v

###############
#
# Utils
#
##############################
clean:
	rm -rf $(BUILD_DIR)/$(OS_ARCH)

clean-all: clean
	rm -rf $(BUILD_DIR)

fmtcheck:
	$(DEV_DIR)/utils/fmtcheck.sh

.PHONY: $(BUILD_DIR) clean build build-test test test-unit test-bogo test-interop
