# Constants
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH))/..)
DEV_DIR      = $(PRJ_DIR)/_dev
# Results will be produced in this directory (can be provided by a caller)
BUILD_DIR   ?= $(PRJ_DIR)/_dev/GOROOT

# Compiler
GO ?= go
DOCKER ?= docker
GIT ?= git

# Build environment
OS          ?= $(shell $(GO) env GOHOSTOS)
ARCH        ?= $(shell $(GO) env GOHOSTARCH)
OS_ARCH     := $(OS)_$(ARCH)
VER_OS_ARCH := $(shell $(GO) version | cut -d' ' -f 3)_$(OS)_$(ARCH)
VER_MAJOR   := $(shell $(GO) version | cut -d' ' -f 3 | cut -d. -f1-2)
GOROOT_ENV  ?= $(shell $(GO) env GOROOT)
GOROOT_LOCAL = $(BUILD_DIR)/$(OS_ARCH)
# Flag indicates wheter invoke "go install -race std". Supported only on amd64 with CGO enabled
INSTALL_RACE:= $(words $(filter $(ARCH)_$(shell go env CGO_ENABLED), amd64_1))

# Test targets used for compatibility testing
TARGET_TEST_COMPAT=boring picotls tstclnt

# Some target-specific constants
BORINGSSL_REVISION=ff433815b51c34496bb6bea13e73e29e5c278238
BOGO_DOCKER_TRIS_LOCATION=/go/src/github.com/cloudflare/tls-tris

TRIS_SOURCES := $(wildcard $(PRJ_DIR)/*.go)

# SIDH repository
SIDH_REPO  ?= https://github.com/cloudflare/sidh.git
SIDH_REPO_TAG ?= Release_1.0
# NOBS repo (SIKE depends on SHA3)
NOBS_REPO  ?= https://github.com/henrydcase/nobscrypto.git
NOBS_REPO_TAG ?= Release_0.1

###############
#
# Build targets
#
##############################

# Default target must build Go (assumed by _dev/go.sh)
.PHONY: go
go: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)

# Ensure src and src/vendor directories are present when building in parallel)
$(GOROOT_LOCAL)/src/vendor:
	mkdir -p $@

# Replace the local copy if the system Go version has changed.
$(GOROOT_LOCAL)/pkg/.ok_$(VER_OS_ARCH): $(GOROOT_ENV)/pkg | $(GOROOT_LOCAL)/src/vendor
	rm -rf $(GOROOT_LOCAL)/pkg $(GOROOT_LOCAL)/src
	mkdir -p "$(GOROOT_LOCAL)/pkg"
	cp -r $(GOROOT_ENV)/src $(GOROOT_LOCAL)/
	cp -r $(GOROOT_ENV)/pkg/include $(GOROOT_LOCAL)/pkg/
	cp -r $(GOROOT_ENV)/pkg/tool $(GOROOT_LOCAL)/pkg/
# Apply additional patches to stdlib
	for p in $(wildcard $(DEV_DIR)/patches/*); do patch -d "$(GOROOT_LOCAL)" -p1 < "$$p"; done
	touch $@

# Vendor NOBS library
$(GOROOT_LOCAL)/src/vendor/github_com/henrydcase/nobs: | $(GOROOT_LOCAL)/src/vendor
	$(eval TMP_DIR := $(shell mktemp -d))
	$(GIT) clone $(NOBS_REPO) $(TMP_DIR)/nobs
	cd $(TMP_DIR)/nobs; $(GIT) checkout tags/$(NOBS_REPO_TAG)
	perl -pi -e 's/sed -i/perl -pi -e/' $(TMP_DIR)/nobs/Makefile
	cd $(TMP_DIR)/nobs; make vendor-sidh-for-tls
	cp -rf $(TMP_DIR)/nobs/tls_vendor/. $(GOROOT_LOCAL)/src/vendor/
	-rm -rf $(TMP_DIR)

# Vendor SIDH library
$(GOROOT_LOCAL)/src/vendor/github_com/cloudflare/sidh: | $(GOROOT_LOCAL)/src/vendor
	$(eval TMP_DIR := $(shell mktemp -d))
	$(GIT) clone $(SIDH_REPO) $(TMP_DIR)/sidh
	cd $(TMP_DIR)/sidh; $(GIT) checkout tags/$(SIDH_REPO_TAG)
	perl -pi -e 's/sed -i/perl -pi -e/' $(TMP_DIR)/sidh/Makefile
	cd $(TMP_DIR)/sidh; make vendor
	cp -rf $(TMP_DIR)/sidh/build/vendor/. $(GOROOT_LOCAL)/src/vendor/
	-rm -rf $(TMP_DIR)

# Rebuild only on dependency (Go core and vendored deps) and Tris changes.
$(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH): \
	$(GOROOT_LOCAL)/pkg/.ok_$(VER_OS_ARCH) \
	$(GOROOT_LOCAL)/src/vendor/github_com/henrydcase/nobs \
	$(GOROOT_LOCAL)/src/vendor/github_com/cloudflare/sidh \
	$(TRIS_SOURCES)

# Replace the standard TLS implementation by Tris
	rsync -a --delete $(PRJ_DIR)/ $(GOROOT_LOCAL)/src/crypto/tls/ --exclude='[._]*'

# Adjust internal paths https://github.com/cloudflare/tls-tris/issues/166
ifeq ($(VER_MAJOR), go1.12)
	perl -pi -e 's,"golang\.org/x/crypto/,"internal/x/crypto/,' $(GOROOT_LOCAL)/src/crypto/tls/*.go
else ifeq ($(VER_MAJOR), go1.11)
	perl -pi -e 's,"golang\.org/x/crypto/,"golang_org/x/crypto/,' $(GOROOT_LOCAL)/src/crypto/tls/*.go
endif
	perl -pi -e 's,"golang\.org/x/sys/cpu","internal/cpu",' $(GOROOT_LOCAL)/src/crypto/tls/*.go
# Use vendored copy of SIDH and SIKE.
	perl -pi -e 's,"github\.com/,"github_com/,' $(GOROOT_LOCAL)/src/crypto/tls/*.go

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
	$(DEV_DIR)/interop_test_runner.py -v

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
