# Makefile
include ../edge-cloud/Makedefs

EDGE_CLOUD_VERSION = heads/master

export GO111MODULE=on

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
	@if ! test "$(CURRENT_EDGE_CLOUD_VERSION)" = "$(EDGE_CLOUD_VERSION)"; then \
		echo; \
		echo "NOTE: edge-cloud repo branch/tag is NOT \"$(EDGE_CLOUD_VERSION)\""; \
		echo; \
	fi

edge-cloud-version-set:
	@echo "Setting edge-cloud repo branch/tag to $(EDGE_CLOUD_VERSION)"
	git -C ../edge-cloud checkout $(EDGE_CLOUD_VERSION)

build-internal:
	go install ./fixmod
	fixmod -srcRepo ../edge-cloud
	go install ./protoc-gen-mc2
	make -f proto.make
	go build ./...
	go build -buildmode=plugin -o ${GOPATH}/plugins/platforms.so plugin/*.go
	go vet ./...

install-edge-cloud:
	make -C ../edge-cloud install

install-internal:
	go install ./...

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

#
# Test
#

UNIT_TEST_LOG = /tmp/edge-cloud-infra-unit-test.log

unit-test:
	go test ./... > $(UNIT_TEST_LOG) || !(grep FAIL $(UNIT_TEST_LOG))

test:
	e2e-tests -testfile ./e2e-tests/testfiles/regression_run.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml
	make -C ../edge-cloud test

test-debug:
	e2e-tests -testfile ./e2e-tests/testfiles/regression_run.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp
	make -C ../edge-cloud test-debug

# start/restart local processes to run individual python or other tests against
test-start:
	e2e-tests -testfile ../edge-cloud/setup-env/e2e-tests/testfiles/deploy_start_create.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

# restart process, clean data
test-reset:
	e2e-tests -testfile ../edge-cloud/setup-env/e2e-tests/testfiles/deploy_reset_create.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

test-stop:
	e2e-tests -testfile ../edge-cloud/setup-env/e2e-tests/testfiles/stop_cleanup.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

# QA testing - manual
test-robot-start:
	e2e-tests -testfile ./e2e-tests/testfiles/deploy_start_create_automation.yml -setupfile ./e2e-tests/setups/local_multi_automation.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

test-robot-stop:
	e2e-tests -testfile ./e2e-tests/testfiles/stop_cleanup.yml -setupfile ./e2e-tests/setups/local_multi_automation.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

## note: DIND requires make install-dind from edge-cloud to be run once
test-dind-start:
	e2e-tests -testfile ./e2e-tests/testfiles/deploy_start_create_dind.yml -setupfile ./e2e-tests/setups/local_dind.yml -varsfile ./e2e-tests/vars.yml -notimestamp -stop

test-dind-stop:
	e2e-tests -testfile ./e2e-tests/testfiles/delete_dind_stop_cleanup.yml -setupfile ./e2e-tests/setups/local_dind.yml -varsfile ./e2e-tests/vars.yml -notimestamp
