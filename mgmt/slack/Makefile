IMAGE = slack-org-mgmt
VERSION = 1.2.3
REGISTRY = registry.mobiledgex.net:5000/mobiledgex

build:
	docker build -t $(IMAGE):$(VERSION) .
	docker tag $(IMAGE):$(VERSION) $(REGISTRY)/$(IMAGE):$(VERSION)

publish: build
	docker push $(REGISTRY)/$(IMAGE):$(VERSION)
