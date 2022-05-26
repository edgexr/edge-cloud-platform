# Makefile
include Makedefs

GOVERS = $(shell go version | awk '{print $$3}' | cut -d. -f1,2)

EDGE_CLOUD_BASE_IMAGE = $(REGISTRY)/edge-cloud-base-image@sha256:97e1ed8e6d9ad5cb5b34b9945d1c128e2fc1928a5c10772701599486db175bf7

export GO111MODULE=on

all: build install

linux: build-linux install-linux

check-vers:
	@if test $(GOVERS) != go1.18; then \
		echo "Go version is $(GOVERS)"; \
		echo "See https://mobiledgex.atlassian.net/wiki/spaces/SWDEV/pages/307986555/Upgrade+to+go+1.12"; \
		exit 2; \
	fi

APICOMMENTS = ./mc/ormapi/api.comments.go

build: check-vers
	(cd pkg/version; ./version.sh)
	go install \
		github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway \
		github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger \
		github.com/gogo/protobuf/protoc-gen-gogofast
	make -C tools/protogen
	make -C tools/edgeprotogen
	go install \
		./tools/protoc-gen-gomex \
		./tools/protoc-gen-test \
		./tools/protoc-gen-cmd \
		./tools/protoc-gen-notify \
		./tools/protoc-gen-controller \
		./tools/protoc-gen-controller-test \
		./tools/protoc-gen-mc2
	make -C pkg/log
	make -C api/dme-proto
	make -C api/edgeproto
	make -C test/testgen
	make -C pkg/vault/letsencrypt-plugin letsencrypt/version.go
	(cd pkg/tls; ./gen-test-certs.sh)
	go install ./pkg/mcctl/genmctestclient
	genmctestclient > ./pkg/mcctl/mctestclient/mctestclient_generatedfuncs.go
	go build ./...
	go build -buildmode=plugin -o ${GOPATH}/plugins/platforms.so pkg/plugin/platform/*.go
	go build -buildmode=plugin -o ${GOPATH}/plugins/edgeevents.so pkg/plugin/edgeevents/*.go
	go vet ./...

build-linux:
	${LINUX_XCOMPILE_ENV} go build ./...
	make -C d-match-engine linux

build-docker:
	rsync --checksum .dockerignore ../.dockerignore
	docker buildx build --push \
		--build-arg BUILD_TAG="$(shell git describe --always --dirty=+), $(shell date +'%Y-%m-%d'), ${TAG}" \
		--build-arg EDGE_CLOUD_BASE_IMAGE=$(EDGE_CLOUD_BASE_IMAGE) \
		--build-arg REGISTRY=$(REGISTRY) \
		-t $(REGISTRY)/edge-cloud:$(TAG) -f build/docker/Dockerfile.edge-cloud ..
	for COMP in alertmgr-sidecar autoprov cluster-svc controller crm dme edgeturn frm mc notifyroot; do \
		docker buildx build --push -t $(REGISTRY)/edge-cloud-$$COMP:$(TAG) \
			--build-arg ALLINONE=$(REGISTRY)/edge-cloud:$(TAG) \
			--build-arg EDGE_CLOUD_BASE_IMAGE=$(EDGE_CLOUD_BASE_IMAGE) \
			-f build/docker/Dockerfile.$$COMP docker || exit 1; \
	done

build-nightly: REGISTRY = harbor.mobiledgex.net/mobiledgex
build-nightly: build-docker
	docker tag mobiledgex/edge-cloud:$(TAG) $(REGISTRY)/edge-cloud:nightly
	docker push $(REGISTRY)/edge-cloud:nightly

install:
	go install ./...

install-linux:
	${LINUX_XCOMPILE_ENV} go install ./...

GOGOPROTO	= $(shell GO111MODULE=on go list -f '{{ .Dir }}' -m github.com/gogo/protobuf)
GRPCGATEWAY	= $(shell GO111MODULE=on go list -f '{{ .Dir }}' -m github.com/grpc-ecosystem/grpc-gateway)

tools:
	make -f Makefile.tools

doc:
	make -C edgeproto doc
	go install ./protoc-gen-mc2
	make -f proto.make
	go install ./doc/swaggerfix
	swagger generate spec -i ./doc/init.json -o ./doc/apidocs.swagger.json --scan-models
	swaggerfix --custom ./doc/custom.yaml ./doc/apidocs.swagger.json

external-doc:
	make -C edgeproto external-doc

doc-local-server:
	docker run --rm -p 1081:80 \
		-v "$(shell pwd)/doc/apidocs.swagger.json:/usr/share/nginx/html/swagger.json" \
		-e SPEC_URL=swagger.json \
		-e REDOC_OPTIONS='sort-props-alphabetically=\"true\"' \
		redocly/redoc:v2.0.0-rc.23

third_party:
	parsedeps --gennotice ./cmd/crmserver ./cmd/controller ./cmd/dme-server ./cmd/cluster-svc ./cmd/edgeturn ./cmd/notifyroot ./pkg/plugin/platform/ ./pkg/plugin/edgeevents ./cmd/shepherd ./pkg/shepherd_platform ./cmd/mc ./cmd/alertmgr-sidecar ./cmd/autoprov> THIRD-PARTY-NOTICES

$(APICOMMENTS): ./tools/apidoc/apidoc.go ./api/ormapi/api.go ./api/ormapi/federation_api.go
	go install ./tools/apidoc
	apidoc --apiFile ./api/ormapi/api.go --apiFile ./api/ormapi/federation_api.go --outFile ./api/ormapi/api.comments.go

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

unit-test:
	go test ./... > $(UNIT_TEST_LOG) || \
		((grep -A6 "\--- FAIL:" $(UNIT_TEST_LOG) || \
		grep -A20 "panic: " $(UNIT_TEST_LOG) || \
		grep -A2 "FATAL" $(UNIT_TEST_LOG)) && \
		grep "FAIL\tgithub.com" $(UNIT_TEST_LOG))

test-all:
	e2e-tests -testfile ./test/e2e-tests/testfiles/regression_run.yml -setupfile ./test/e2e-tests/setups/local_multi.yml -varsfile ./test/e2e-tests/vars.yml

test-debug:
	e2e-tests -testfile ./test/e2e-tests/testfiles/regression_run.yml -setupfile ./test/e2e-tests/setups/local_multi.yml -varsfile ./test/e2e-tests/vars.yml -stop -notimestamp

# start/restart local processes to run individual python or other tests against
test-start:
	e2e-tests -testfile ./test/e2e-tests/testfiles/deploy_start_create.yml -setupfile ./test/e2e-tests/setups/local_multi.yml -varsfile ./test/e2e-tests/vars.yml -stop -notimestamp

# restart process, clean data
test-reset:
	e2e-tests -testfile ./test/test/e2e-tests/testfiles/deploy_reset_create.yml -setupfile ./test/e2e-tests/setups/local_multi.yml -varsfile ./test/e2e-tests/vars.yml -stop -notimestamp

test-stop:
	e2e-tests -testfile ./test/e2e-tests/testfiles/stop_cleanup.yml -setupfile ./test/e2e-tests/setups/local_multi.yml -varsfile ./test/e2e-tests/vars.yml -notimestamp

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

build-ansible:
	docker buildx build --load \
		-t deploy -f docker/Dockerfile.ansible ./ansible

clean: check-vers
	go clean ./...
