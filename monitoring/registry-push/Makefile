TAG ?= $(shell date +'%Y-%m-%d')

IMAGE = mobiledgex/gitlab-slack-notify
REGISTRY = registry.mobiledgex.net:5000

build:
	docker build -t $(IMAGE):$(TAG) .
	docker tag $(IMAGE):$(TAG) $(REGISTRY)/$(IMAGE):$(TAG)

publish: build
	docker push $(REGISTRY)/$(IMAGE):$(TAG)
