TAG ?= $(shell git describe --tags)
REGISTRY ?= harbor.mobiledgex.net/mobiledgex-dev

build:
	docker build -t mobiledgex/edge-cloud-base-image:$(TAG) -f Dockerfile.edge-cloud-base-image .
	docker tag mobiledgex/edge-cloud-base-image:$(TAG) $(REGISTRY)/edge-cloud-base-image:$(TAG)

publish: build
	docker push $(REGISTRY)/edge-cloud-base-image:$(TAG)

build-influxdb-backup:
	docker build -t mobiledgex/influxdb-backup:$(TAG) -f Dockerfile.influxdb-backup .
	docker tag mobiledgex/influxdb-backup:$(TAG) $(REGISTRY)/influxdb-backup:$(TAG)

publish-influxdb-backup: build-influxdb-backup
	docker push $(REGISTRY)/influxdb-backup:$(TAG)
