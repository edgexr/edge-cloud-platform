TAG ?= $(shell git describe --tags)
REGISTRY ?= ghcr.io/edgexr

build:
	docker build -t edgexr/edge-cloud-base-image:$(TAG) -f Dockerfile.edge-cloud-base-image .
	docker tag edgexr/edge-cloud-base-image:$(TAG) $(REGISTRY)/edge-cloud-base-image:$(TAG)

publish: build
	docker push $(REGISTRY)/edge-cloud-base-image:$(TAG)

build-influxdb-backup:
	docker build -t edgexr/influxdb-backup:$(TAG) -f Dockerfile.influxdb-backup .
	docker tag edgexr/influxdb-backup:$(TAG) $(REGISTRY)/influxdb-backup:$(TAG)

publish-influxdb-backup: build-influxdb-backup
	docker push $(REGISTRY)/influxdb-backup:$(TAG)

GOVERS = go1.18.1

gobuild:
	docker build -t edgexr/build:$(GOVERS) -f Dockerfile.build .
	docker tag edgexr/build:$(GOVERS) $(REGISTRY)/build:$(GOVERS)

gobuild-publish:
	docker push $(REGISTRY)/gobuild:$(GOVERS)
