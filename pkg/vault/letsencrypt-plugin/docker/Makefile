TAG ?= $(shell date +'%Y-%m-%d')

IMAGE = edgexr/certgen
REGISTRY = ghcr.io

build:
	docker build -t $(IMAGE):$(TAG) .
	docker tag $(IMAGE):$(TAG) $(REGISTRY)/$(IMAGE):$(TAG)

publish: build
	docker push $(REGISTRY)/$(IMAGE):$(TAG)
