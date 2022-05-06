TAG ?= $(shell date +'%Y-%m-%d')

IMAGE = mobiledgex/certgen
REGISTRY = harbor.mobiledgex.net

build:
	docker build -t $(IMAGE):$(TAG) .
	docker tag $(IMAGE):$(TAG) $(REGISTRY)/$(IMAGE):$(TAG)

publish: build
	docker push $(REGISTRY)/$(IMAGE):$(TAG)
