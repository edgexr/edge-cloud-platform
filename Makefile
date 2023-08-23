# Makefile
include Makedefs

GOVERS = $(shell go version | awk '{print $$3}' | cut -d. -f1,2)

GO_BUILD_FLAGS = --trimpath --buildvcs=false

export GO111MODULE=on

all: build install

linux: build-linux install-linux

check-go-vers:
	@if test $(GOVERS) != go1.18; then \
		echo "Go version must be $(GOVERS)"; \
		exit 2; \
	fi

APICOMMENTS = ./mc/ormapi/api.comments.go

gen-test-certs:
	(cd pkg/tls; ./gen-test-certs.sh)

gen-vers:
	(cd pkg/version; ./version.sh)

generate: check-go-vers $(APICOMMENTS) gen-vers
	go install $(GO_BUILD_FLAGS) \
		github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway \
		github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger \
		github.com/gogo/protobuf/protoc-gen-gogofast
	make -C tools/protogen
	make -C tools/edgeprotogen
	go install $(GO_BUILD_FLAGS) \
		./tools/protoc-gen-gomex \
		./tools/protoc-gen-test \
		./tools/protoc-gen-cmd \
		./tools/protoc-gen-notify \
		./tools/protoc-gen-controller \
		./tools/protoc-gen-controller-test \
		./tools/protoc-gen-mc2 \
		./tools/protoc-gen-redisapi
	make -C pkg/log
	make -C api/dme-proto
	make -C api/edgeproto
	make -C test/testgen
	go install $(GO_BUILD_FLAGS) ./pkg/mcctl/genmctestclient
	genmctestclient > ./pkg/mcctl/mctestclient/mctestclient_generatedfuncs.go

gobuild: check-go-vers gen-vers
	go build $(GO_BUILD_FLAGS) ./...
	go vet ./...

build: generate gobuild

build-linux:
	${LINUX_XCOMPILE_ENV} go build $(GO_BUILD_FLAGS) ./...
	make -C d-match-engine linux

install:
	go install $(GO_BUILD_FLAGS) ./...

install-linux:
	${LINUX_XCOMPILE_ENV} go install $(GO_BUILD_FLAGS) ./...

GOGOPROTO	= $(shell GO111MODULE=on go list -f '{{ .Dir }}' -m github.com/gogo/protobuf)
GRPCGATEWAY	= $(shell GO111MODULE=on go list -f '{{ .Dir }}' -m github.com/grpc-ecosystem/grpc-gateway)

tools:
	make -f Makefile.tools

external-doc:
	make -C edgeproto external-doc

third_party:
	parsedeps --gennotice ./cmd/crmserver ./cmd/controller ./cmd/dme-server ./cmd/cluster-svc ./cmd/edgeturn ./cmd/notifyroot ./pkg/plugin/platform/ ./pkg/plugin/edgeevents ./cmd/shepherd ./pkg/shepherd_platform ./cmd/mc ./cmd/alertmgr-sidecar ./cmd/autoprov> THIRD-PARTY-NOTICES

$(APICOMMENTS): ./tools/apidoc/apidoc.go ./api/ormapi/api.go ./api/ormapi/federation_api.go
	go install ./tools/apidoc
	apidoc --apiFile ./api/ormapi/api.go --apiFile ./api/ormapi/federation_api.go --outFile ./api/ormapi/api.comments.go

api-comments: $(APICOMMENTS)

# adds license header to all files, see https://github.com/google/addlicense
addlicense:
	addlicense -c "EdgeXR, Inc" -l apache .

lint:
	(cd $(GOPATH)/src/github.com/uber/prototool; go install ./cmd/prototool)
	$(RM) link-gogo-protobuf
	$(RM) link-grpc-gateway
	ln -s $(GOGOPROTO) link-gogo-protobuf
	ln -s $(GRPCGATEWAY) link-grpc-gateway
	prototool lint edgeproto
	prototool lint d-match-engine

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

UNIT_TEST_LOG ?= /tmp/edge-cloud-unit-test.log

unit-test: gen-test-certs
	go test -timeout=3m ./... > $(UNIT_TEST_LOG) || \
		((grep -A6 "\--- FAIL:" $(UNIT_TEST_LOG) || \
		grep -A20 "panic: " $(UNIT_TEST_LOG) || \
		grep -A2 "FATAL" $(UNIT_TEST_LOG)) && \
		grep "FAIL\tgithub.com" $(UNIT_TEST_LOG))

E2E_SETUP	= ./test/e2e-tests/setups/local_multi.yml
E2E_VARS	= ./test/e2e-tests/vars.yml
E2E_TESTFILE	= ./test/e2e-tests/testfiles/regression_run.yml
E2E_TESTSTART	= ./test/e2e-tests/testfiles/deploy_start_create.yml
E2E_TESTRESET	= ./test/test/e2e-tests/testfiles/deploy_reset_create.yml
E2E_TESTSTOP	= ./test/e2e-tests/testfiles/stop_cleanup.yml

test:
	e2e-tests -testfile $(E2E_TESTFILE) -setupfile $(E2E_SETUP) -varsfile $(E2E_VARS)

test-debug:
	e2e-tests -testfile $(E2E_TESTFILE) -setupfile $(E2E_SETUP) -varsfile $(E2E_VARS) -stop -notimestamp

test-extra:
	e2e-tests -testfile $(E2E_TESTFILE) -setupfile $(E2E_SETUP) -varsfile $(E2E_VARS) -runextra

test-extra-debug:
	e2e-tests -testfile $(E2E_TESTFILE) -setupfile $(E2E_SETUP) -varsfile $(E2E_VARS) -runextra -stop -notimestamp

# start/restart local processes to run individual python or other tests against
test-start:
	e2e-tests -testfile $(E2E_TESTSTART) -setupfile $(E2E_SETUP) -varsfile $(E2E_VARS) -stop -notimestamp

# restart process, clean data
test-reset:
	e2e-tests -testfile $(E2E_TESTRESET) -setupfile $(E2E_SETUP) -varsfile $(E2E_VARS) -stop -notimestamp

test-stop:
	e2e-tests -testfile $(E2E_TESTSTOP) -setupfile $(E2E_SETUP) -varsfile $(E2E_VARS) -notimestamp

# QA testing - manual
test-robot-start:
	e2e-tests -testfile ./test/e2e-tests/testfiles/deploy_start_create_automation.yml -setupfile ./test/e2e-tests/setups/local_multi_automation.yml -varsfile ./test/e2e-tests/vars.yml -stop -notimestamp

test-robot-stop:
	e2e-tests -testfile ./test/e2e-tests/testfiles/stop_cleanup.yml -setupfile ./test/e2e-tests/setups/local_multi_automation.yml -varsfile ./test/e2e-tests/vars.yml -stop -notimestamp

# Kind local k8s testing
kind-test-start:
	e2e-tests -testfile ./test/e2e-tests/testfiles/kind_deploy_start_create.yml -setupfile ./test/e2e-tests/setups/local_multi.yml -varsfile ./test/e2e-tests/vars.yml -stop -notimestamp

kind-test-stop:
	e2e-tests -testfile ./test/e2e-tests/testfiles/stop_cleanup.yml -setupfile ./test/e2e-tests/setups/local_multi.yml -varsfile ./test/e2e-tests/vars.yml -notimestamp

## note: edgebox requires make install-dind from edge-cloud to be run once
edgebox-start:
	e2e-tests -testfile ./test/e2e-tests/testfiles/deploy_start_create_edgebox.yml -setupfile ./test/e2e-tests/setups/local_edgebox.yml -varsfile ./test/e2e-tests/vars.yml -notimestamp -stop

edgebox-stop:
	e2e-tests -testfile ./test/e2e-tests/testfiles/delete_edgebox_stop_cleanup.yml -setupfile ./test/e2e-tests/setups/local_edgebox.yml -varsfile ./test/e2e-tests/vars.yml -notimestamp

chef-start:
	e2e-tests -testfile ./test/e2e-tests/testfiles/deploy_start_create_chef.yml -setupfile ./test/e2e-tests/setups/local_chef.yml -varsfile ./test/e2e-tests/vars.yml -notimestamp -stop

chef-stop:
	e2e-tests -testfile ./test/e2e-tests/testfiles/delete_chef_stop_cleanup.yml -setupfile ./test/e2e-tests/setups/local_chef.yml -varsfile ./test/e2e-tests/vars.yml -notimestamp

edgebox-docker-start:
	e2e-tests -testfile ./test/e2e-tests/testfiles/deploy_start_create_edgebox_docker.yml -setupfile ./test/e2e-tests/setups/local_edgebox.yml -varsfile ./test/e2e-tests/vars.yml -notimestamp -stop

edgebox-docker-stop:
	e2e-tests -testfile ./test/e2e-tests/testfiles/delete_edgebox_docker_stop_cleanup.yml -setupfile ./test/e2e-tests/setups/local_edgebox.yml -varsfile ./test/e2e-tests/vars.yml -notimestamp

# for rebuilding just the e2e tools
test-tools:
	go install ./test/e2e-tests/cmd/e2e-tests \
		./test/e2e-tests/cmd/test-mex-infra

#test:
#	e2e-tests -testfile ./setup-env/e2e-tests/testfiles/regression_group.yml -setupfile ./setup-env/e2e-tests/setups/local_multi.yml

#test-debug:
#	e2e-tests -testfile ./setup-env/e2e-tests/testfiles/regression_group.yml -setupfile ./setup-env/e2e-tests/setups/local_multi.yml -stop -notimestamp

# start/restart local processes to run individual python or other tests against
#test-start:
#	e2e-tests -testfile ./setup-env/e2e-tests/testfiles/deploy_start_create.yml -setupfile ./setup-env/e2e-tests/setups/local_multi.yml -stop -notimestamp

# restart process, clean data
#test-reset:
#	e2e-tests -testfile ./setup-env/e2e-tests/testfiles/deploy_reset_create.yml -setupfile ./setup-env/e2e-tests/setups/local_multi.yml -stop -notimestamp

#test-stop:
#	e2e-tests -testfile ./setup-env/e2e-tests/testfiles/delete_stop_create.yml -setupfile ./setup-env/e2e-tests/setups/local_multi.yml -notimestamp

test-sdk:
	e2e-tests -testfile ./setup-env/e2e-tests/testfiles/sdk_test/stop_start_create_sdk.yml -setupfile ./setup-env/e2e-tests/setups/local_sdk.yml

# requires kind to be installed
#test-kind-start:
#	e2e-tests -testfile ./setup-env/e2e-tests/testfiles/deploy_start_create_kind.yml -setupfile ./setup-env/e2e-tests/setups/local_dind.yml -notimestamp -stop

#test-kind-stop:
#	e2e-tests -testfile ./setup-env/e2e-tests/testfiles/delete_kind_stop_cleanup.yml -setupfile ./setup-env/e2e-tests/setups/local_dind.yml -notimestamp

build-edgebox:
	mkdir edgebox_bin
	mkdir edgebox_bin/ansible
	rsync -a ansible/playbooks edgebox_bin/ansible
	rsync -a e2e-tests edgebox_bin
	rsync -a ../edge-cloud/setup-env/e2e-tests/data edgebox_bin/e2e-tests/edgebox
	rsync -a $(GOPATH)/plugins edgebox_bin
	rsync -a $(GOPATH)/bin/crmserver \
		 $(GOPATH)/bin/e2e-tests \
		 $(GOPATH)/bin/edgectl \
		 $(GOPATH)/bin/mcctl \
		 $(GOPATH)/bin/test-mex \
		 $(GOPATH)/bin/test-mex-infra \
		 edgebox_bin/bin
	mv edgebox_bin/e2e-tests/edgebox/edgebox edgebox_bin
	mv edgebox_bin/e2e-tests/edgebox/requirements.txt edgebox_bin
	tar cf edgebox-bin-$(TAG).tar edgebox_bin
	bzip2 edgebox-bin-$(TAG).tar
	$(RM) -r edgebox_bin

clean-edgebox:
	rm -rf edgebox_bin

clean: check-go-vers
	go clean ./...

.PHONY: clean doc test
