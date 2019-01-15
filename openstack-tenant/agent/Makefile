PKG = "mexosagent"
GOPATH ?= $(shell go env GOPATH)
GO_PACKAGES := $(shell go list ./... | grep -v /vendor/)
PROGRAM = mexosagent
API_FILES = api/mexosagent.pb.go api/mexosagent.pb.gw.go api/mexosagent.swagger.json

.PHONY: build api dep test race msan

#default: build docker-build docker-push
default: build install

linux: build-linux install-linux

docker-build:
	./docker-build.sh

# docker login first!
docker-push:
	docker tag mobiledgex/mexosagent registry.mobiledgex.net:5000/mobiledgex/mexosagent
	docker push registry.mobiledgex.net:5000/mobiledgex/mexosagent

build: api dep ## Build mexosagent
	go get ./...
	mkdir -p build
	CGO_ENABLED=0 go build -o build/${PROGRAM} .

build-linux: api dep ## Build mexosagent for linux
	go get ./...
	mkdir -p build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/${PROGRAM} .


install: 
	go install ./...
	ln -fs ${GOPATH}/bin/agent ${GOPATH}/bin/mexosagent

install-linux:
	GOOS=linux GOARCH=amd64 go install ./...
	ln -fs ${GOPATH}/bin/linux_amd64/agent ${GOPATH}/bin/linux_amd64/mexosagent

dep: api ## Fetch dependencies
	@go get ./...

api: $(API_FILES) ## Auto-generate gRPC/REST Go sources

api/mexosagent.pb.go: api/mexosagent.proto
	@protoc -I. \
		-I${GOPATH}/src \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		--go_out=plugins=grpc:. \
		api/mexosagent.proto

api/mexosagent.pb.gw.go: api/mexosagent.proto
	@protoc -I. \
		-I${GOPATH}/src \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		--grpc-gateway_out=logtostderr=true:. \
		api/mexosagent.proto

api/mexosagent.swagger.json: api/mexosagent.proto
	@protoc -I. \
		-I${GOPATH}/src \
		-I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		--swagger_out=logtostderr=true:. \
		api/mexosagent.proto

clean: ## Clean compiled binaries
	@rm -f build/${PROGRAM}

realclean: ## Clean compiled binaries and all generated files
	@rm -f build/${PROGRAM}
	@rm -f ${API_FILES}

test: dep ## Run tests
	@go test -short ${GO_PACKAGES}

race: dep ## Run tests with race detector
	@go test -race -short ${GO_PACKAGES}

msan: dep ## Run tests with memory sanitizer
	@go test -msan -short ${GO_PACKAGES}
