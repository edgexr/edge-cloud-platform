TAG ?= $(shell git describe --tags)
# edge-cloud version tag
VERSION ?= $(shell echo $$USER | tr -cd 'a-zA-Z' )-$(shell date +'%Y-%m-%d' )
REGISTRY ?= ghcr.io/edgexr
PUSH ?= --push
KUBECTL_WRAPPER_ARCHIVES ?= https://github.com/edgexr/kubectl/archive/refs/tags
KUBECTL_WRAPPER_VERSION ?= 0.0.2

# TOP refers to repository root
TOP = ../..

build-edge-cloud-infra-base:
	docker build -t edgexr/edge-cloud-infra-base:$(TAG) -f Dockerfile.edge-cloud-infra-base .
	docker tag edgexr/edge-cloud-infra-base:$(TAG) $(REGISTRY)/edge-cloud-infra-base:$(TAG)

publish-edge-cloud-infra-base:
	docker push $(REGISTRY)/edge-cloud-infra-base:$(TAG)

GOVERS = go1.22.9

gobuild:
	docker build -t edgexr/build:$(GOVERS) -f Dockerfile.build .
	docker tag edgexr/build:$(GOVERS) $(REGISTRY)/build:$(GOVERS)

gobuild-publish:
	docker push $(REGISTRY)/build:$(GOVERS)

alpine-wget:
	docker build -t edgexr/alpine-wget:$(VERSION) -f Dockerfile.alpine-wget .
	docker tag edgexr/alpine-wget:$(VERSION) $(REGISTRY)/alpine-wget:$(VERSION)
	docker push $(REGISTRY)/alpine-wget:$(VERSION)

# Image to be used for services that don't need infra-specific clients
# Ideally this should be a non-debug version, but using debug for
# now to include shell.
NON_INFRA_BASE_IMAGE ?= gcr.io/distroless/base-debian12:debug

EDGE_CLOUD_INFRA_BASE ?= $(REGISTRY)/edge-cloud-infra-base@sha256:d251d83ad71e4ae5b45f0573f57f3e99298d41f978c1ca16430c5ec8dc5be2e1

EDGE_CLOUD_IMAGE ?= $(REGISTRY)/edge-cloud

build-platform-common:
	docker buildx build \
		--build-arg BUILD_TAG=$(VERSION) \
		--build-arg NON_INFRA_BASE_IMAGE=$(NON_INFRA_BASE_IMAGE) \
		--build-arg EDGE_CLOUD_INFRA_BASE=$(EDGE_CLOUD_INFRA_BASE) \
		--build-arg REGISTRY=$(REGISTRY) \
		--build-arg KUBECTL_WRAPPER_ARCHIVES=$(KUBECTL_WRAPPER_ARCHIVES) \
		--build-arg KUBECTL_WRAPPER_VERSION=$(KUBECTL_WRAPPER_VERSION) \
		-t $(EDGE_CLOUD_IMAGE):$(VERSION) -f Dockerfile.edge-cloud-platform $(TOP)

build-platform: build-platform-common
	for COMP in autoprov cluster-svc controller ccrm crm dme edgeturn notifyroot; do \
		docker buildx build $(PUSH) -t $(EDGE_CLOUD_IMAGE)-$$COMP:$(VERSION) \
			--build-arg NON_INFRA_BASE_IMAGE=$(NON_INFRA_BASE_IMAGE) \
			--build-arg ALLINONE=$(EDGE_CLOUD_IMAGE):$(VERSION) \
			--build-arg EDGE_CLOUD_INFRA_BASE=$(EDGE_CLOUD_INFRA_BASE) \
			-f Dockerfile.$$COMP . || exit 1; \
	done

build-platform-local: PUSH =
build-platform-local: build-platform
