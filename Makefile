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

build-vers:
	mkdir -p version
	(cd version; ../../edge-cloud/version/version.sh "Infra")

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

APICOMMENTS = ./mc/ormapi/api.comments.go

build-internal: build-vers $(APICOMMENTS)
	go install ./fixmod
	fixmod -srcRepo ../edge-cloud -keep github.com/edgexr/edge-cloud
	go install ./protoc-gen-mc2
	make -f proto.make
	make -C vault/letsencrypt-plugin letsencrypt/version.go
	go install ./mc/mcctl/genmctestclient
	genmctestclient > ./mc/mcctl/mctestclient/mctestclient_generatedfuncs.go
	go build ./...
	go build -buildmode=plugin -o ${GOPATH}/plugins/platforms.so plugin/platform/*.go
	go build -buildmode=plugin -o ${GOPATH}/plugins/edgeevents.so plugin/edgeevents/*.go	
	go vet ./...

install-edge-cloud:
	make -C ../edge-cloud install

install-internal:
	go install ./...

$(APICOMMENTS): ./mc/ormapi/apidoc/apidoc.go ./mc/ormapi/api.go ./mc/ormapi/federation_api.go
	go install ./mc/ormapi/apidoc
	apidoc --apiFile ./mc/ormapi/api.go --apiFile ./mc/ormapi/federation_api.go --outFile ./mc/ormapi/api.comments.go

doc:
	go install ./protoc-gen-mc2
	make -f proto.make
	go install ./doc/swaggerfix
	swagger generate spec -i ./doc/init.json -o ./doc/apidocs.swagger.json --scan-models
	swaggerfix --custom ./doc/custom.yaml ./doc/apidocs.swagger.json

doc-local-server:
	docker run --rm -p 1081:80 \
		-v "$(shell pwd)/doc/apidocs.swagger.json:/usr/share/nginx/html/swagger.json" \
		-e SPEC_URL=swagger.json \
		-e REDOC_OPTIONS='sort-props-alphabetically=\"true\"' \
		redocly/redoc:v2.0.0-rc.23

third_party:
	parsedeps --gennotice ../edge-cloud/cloud-resource-manager/cmd/crmserver/ ../edge-cloud/controller ../edge-cloud/d-match-engine/dme-server ../edge-cloud/cluster-svc ../edge-cloud/edgeturn ../edge-cloud/notifyroot ./plugin/platform/ ./plugin/edgeevents ./shepherd ./shepherd/shepherd_platform ./mc ./alertmgr-sidecar ./autoprov > THIRD-PARTY-NOTICES

# adds license header to all files, see https://github.com/google/addlicense
addlicense:
	addlicense -c "EdgeXR, Inc" -l apache .

.PHONY: doc

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

UNIT_TEST_LOG ?= /tmp/edge-cloud-infra-unit-test.log

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
	e2e-tests -testfile ./e2e-tests/testfiles/deploy_start_create.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

# restart process, clean data
test-reset:
	e2e-tests -testfile ../edge-cloud/setup-env/e2e-tests/testfiles/deploy_reset_create.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

test-stop:
	e2e-tests -testfile ./e2e-tests/testfiles/stop_cleanup.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -notimestamp

# QA testing - manual
test-robot-start:
	e2e-tests -testfile ./e2e-tests/testfiles/deploy_start_create_automation.yml -setupfile ./e2e-tests/setups/local_multi_automation.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

test-robot-stop:
	e2e-tests -testfile ./e2e-tests/testfiles/stop_cleanup.yml -setupfile ./e2e-tests/setups/local_multi_automation.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

# Kind local k8s testing
kind-test-start:
	e2e-tests -testfile ./e2e-tests/testfiles/kind_deploy_start_create.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -stop -notimestamp

kind-test-stop:
	e2e-tests -testfile ./e2e-tests/testfiles/stop_cleanup.yml -setupfile ./e2e-tests/setups/local_multi.yml -varsfile ./e2e-tests/vars.yml -notimestamp

## note: edgebox requires make install-dind from edge-cloud to be run once
edgebox-start:
	e2e-tests -testfile ./e2e-tests/testfiles/deploy_start_create_edgebox.yml -setupfile ./e2e-tests/setups/local_edgebox.yml -varsfile ./e2e-tests/vars.yml -notimestamp -stop

edgebox-stop:
	e2e-tests -testfile ./e2e-tests/testfiles/delete_edgebox_stop_cleanup.yml -setupfile ./e2e-tests/setups/local_edgebox.yml -varsfile ./e2e-tests/vars.yml -notimestamp

chef-start:
	e2e-tests -testfile ./e2e-tests/testfiles/deploy_start_create_chef.yml -setupfile ./e2e-tests/setups/local_chef.yml -varsfile ./e2e-tests/vars.yml -notimestamp -stop

chef-stop:
	e2e-tests -testfile ./e2e-tests/testfiles/delete_chef_stop_cleanup.yml -setupfile ./e2e-tests/setups/local_chef.yml -varsfile ./e2e-tests/vars.yml -notimestamp

edgebox-docker-start:
	e2e-tests -testfile ./e2e-tests/testfiles/deploy_start_create_edgebox_docker.yml -setupfile ./e2e-tests/setups/local_edgebox.yml -varsfile ./e2e-tests/vars.yml -notimestamp -stop

edgebox-docker-stop:
	e2e-tests -testfile ./e2e-tests/testfiles/delete_edgebox_docker_stop_cleanup.yml -setupfile ./e2e-tests/setups/local_edgebox.yml -varsfile ./e2e-tests/vars.yml -notimestamp

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
