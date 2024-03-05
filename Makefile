# Makefile
include Makedefs

GOVERS = $(shell go version | awk '{print $$3}' | cut -d. -f1,2)

GO_BUILD_FLAGS = --trimpath --buildvcs=false

export GO111MODULE=on

all: build install

linux: build-linux install-linux

check-go-vers:
	@if test $(GOVERS) != go1.21; then \
		echo "Go version must be $(GOVERS)"; \
		exit 2; \
	fi

gen-test-certs:
	(cd pkg/tls; ./gen-test-certs.sh)

gen-vers:
	(cd pkg/version; ./version.sh)

generate: check-go-vers gen-vers gen-ansible
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
		./tools/protoc-gen-redisapi
	make -C pkg/log
	make -C api/distributed_match_engine
	make -C api/edgeproto
	make -C test/testgen

gen-ansible:
	make -C pkg/ccrm

gobuild: check-go-vers gen-vers gen-ansible
	go build $(GO_BUILD_FLAGS) ./...
	go vet ./...

build: generate gobuild

build-linux:
	${LINUX_XCOMPILE_ENV} go build $(GO_BUILD_FLAGS) ./...
	make -C d-match-engine linux

install:
	go install $(GO_BUILD_FLAGS) ./...

install-unit-test:
	go install $(GO_BUILD_FLAGS) ./cmd/crm

install-linux:
	${LINUX_XCOMPILE_ENV} go install $(GO_BUILD_FLAGS) ./...

GOGOPROTO	= $(shell GO111MODULE=on go list -f '{{ .Dir }}' -m github.com/gogo/protobuf)
GRPCGATEWAY	= $(shell GO111MODULE=on go list -f '{{ .Dir }}' -m github.com/grpc-ecosystem/grpc-gateway)

.PHONY: tools

tools:
	make -f Makefile.tools

external-doc:
	make -C edgeproto external-doc

CMDS	= ./cmd/autoprov ./cmd/ccrm ./cmd/cluster-svc ./cmd/controller ./cmd/crm ./cmd/dme ./cmd/edgeturn ./cmd/notifyroot ./cmd/shepherd ./pkg/platform/ ./pkg/plugin/edgeevents ./pkg/plugin/platform ./pkg/shepherd_platform

third_party:
	parsedeps --gennotice ${CMDS} > THIRD-PARTY-NOTICES

# adds license header to all files, see https://github.com/google/addlicense
addlicense:
	addlicense -c "EdgeXR, Inc" -l apache \
		-ignore pkg/ccrm/test_node_attributes_exp.yml \
		-ignore pkg/platform/common/infracommon/test-netplan-config.yaml \
		-ignore pkg/platform/common/infracommon/test-netplan-config2-expected.yaml \
		-ignore pkg/platform/common/vmlayer/TestSetupForwardingIptables-expected.sh \
		-ignore pkg/platform/common/vmlayer/TestSetupIptablesRulesForRootLB-expected.sh \
		-ignore pkg/proxy/test-envoy-config-expected.yaml \
		-ignore pkg/proxy/test-envoy-sds-expected.yaml \
		.

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
UNIT_TEST_TIMEOUT ?= 3m

unit-test: gen-test-certs gen-ansible
	go test -timeout=$(UNIT_TEST_TIMEOUT) ./... > $(UNIT_TEST_LOG) || \
		((grep -A6 "\--- FAIL:" $(UNIT_TEST_LOG) || \
		grep -A20 "panic: " $(UNIT_TEST_LOG) || \
		grep -A2 "FATAL" $(UNIT_TEST_LOG)) && \
		grep "FAIL\tgithub.com" $(UNIT_TEST_LOG))

clean: check-go-vers
	go clean ./...

.PHONY: clean doc test
