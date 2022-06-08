# Makefile

PROTODEPS	:= $(shell go list -f '{{ .Dir }}' -m \
	github.com/grpc-ecosystem/grpc-gateway \
	github.com/gogo/googleapis \
	github.com/edgexr/edge-cloud-platform)
GW		:= $(word 1,$(PROTODEPS))
APIS		:= $(word 2,$(PROTODEPS))
PROJECT		:= $(word 3,$(PROTODEPS))
EDGEPROTOGENDIR	= $(PROJECT)/tools/edgeprotogen
INCLUDE		= -I. -I${GW} -I${APIS} -I${GOPATH} -I${EDGEPROTOGENDIR}
BUILTIN		= Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,Mgoogle/api/annotations.proto=github.com/gogo/googleapis/google/api,Mgoogle/protobuf/field_mask.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/descriptor.proto=github.com/golang/protobuf/protoc-gen-go/descriptor
DMEDIR		= ${GOPATH}/src/github.com/edgexr/edge-proto/dme
PROTOS		= app-client.proto appcommon.proto dynamic-location-group.proto loc.proto

CMDDIR		= ../../pkg/gencmd

build: $(PROTOS)
	protoc ${INCLUDE} --gomex_out=plugins=grpc+mex,${BUILTIN}:. $(PROTOS)
	protoc ${INCLUDE} --grpc-gateway_out=${BUILTIN}:. $(PROTOS)
	protoc ${INCLUDE} --cmd_out=${BUILTIN}:${CMDDIR} $(PROTOS)

# swagger annotations for REST APIs
# go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
swagger: $(PROTOS)
	protoc ${INCLUDE} --swagger_out=logtostderr=true,allow_merge=true,merge_file_name=app-client:. *.proto

external-swagger: $(PROTOS)
	mkdir -p ./external-doc
	protoc ${INCLUDE} --swagger_out=logtostderr=true,allow_merge=true,config_file=swagger_config.yaml,merge_file_name=app-client:./external-doc *.proto

$(PROTOS):
	ln -sf ${DMEDIR}/$@ $@
