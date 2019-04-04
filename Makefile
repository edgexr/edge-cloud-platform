# Makefile
include ../edge-cloud/Makedefs

all: build-all install-all

build-all: build-edge-cloud build-internal

install-all: install-edge-cloud install-internal

internal: build-internal install-internal

#
# Local OS Target
#

build-edge-cloud:
	make -C ../edge-cloud build

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
