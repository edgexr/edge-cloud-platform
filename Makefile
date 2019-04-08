# Makefile
include ../edge-cloud/Makedefs

EDGE_CLOUD_VERSION = heads/master

all: build-all install-all

build-all: build-edge-cloud build-internal

install-all: install-edge-cloud install-internal

internal: build-internal install-internal

dep:
	dep ensure -vendor-only

#
# Local OS Target
#

build-edge-cloud: edge-cloud-version-check
	make -C ../edge-cloud build

CURRENT_EDGE_CLOUD_VERSION = $(shell git -C ../edge-cloud describe --tags --all)
edge-cloud-version-check:
	@echo "Ensuring edge-cloud repo branch/tag is $(EDGE_CLOUD_VERSION)"
	test "$(CURRENT_EDGE_CLOUD_VERSION)" = "$(EDGE_CLOUD_VERSION)"

edge-cloud-version-set:
	@echo "Setting edge-cloud repo branch/tag to $(EDGE_CLOUD_VERSION)"
	git -C ../edge-cloud checkout $(EDGE_CLOUD_VERSION)

build-internal:
	make -C ./openstack-tenant/agent/
	go build -buildmode=plugin -o ${GOPATH}/plugins/platforms.so plugin/*.go
	go vet ./...

install-edge-cloud:
	make -C ../edge-cloud install

install-internal:
	go install ./...

install-dind:
	./install-dind.sh

#
# Linux Target OS
#

linux: build-linux install-linux

build-linux: build-edge-cloud-linux build-internal-linux

build-edge-cloud-linux:
	make -C ../edge-cloud build-linux

build-internal-linux:
	make -C ./openstack-tenant/agent/ linux
	go build ./...
	go vet ./...

install-linux: install-edge-cloud-linux install-internal-linux

install-edge-cloud-linux:
	make -C ../edge-cloud install-linux

install-internal-linux:
	${LINUX_XCOMPILE_ENV} go install ./...
