# Makefile

GW		= $(shell go list -f '{{ .Dir }}' -m github.com/grpc-ecosystem/grpc-gateway)
APIS		= $(shell go list -f '{{ .Dir }}' -m github.com/gogo/googleapis)
PROJECT		= $(shell go list -f '{{ .Dir }}' -m github.com/edgexr/edge-cloud-platform)
PROTOC		= $(shell which protoc)
GOMEX		= $(shell which protoc-gen-gomex)
GATEWAYGEN	= $(shell which protoc-gen-grpc-gateway)
CMDGEN		= $(shell which protoc-gen-cmd)
EDGEPROTOGENDIR	= $(PROJECT)/tools/edgeprotogen
INCLUDE		= -I. -I${GW} -I${APIS} -I${GOPATH} -I${EDGEPROTOGENDIR}
BUILTIN		= Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,Mgoogle/api/annotations.proto=github.com/gogo/googleapis/google/api,Mgoogle/protobuf/field_mask.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/descriptor.proto=github.com/golang/protobuf/protoc-gen-go/descriptor
DMEDIR		= ${GOPATH}/src/github.com/edgexr/edge-proto/dme
PROTOS		= $(shell cd $(DMEDIR); ls *.proto)

CMDDIR		= ../../pkg/gencmd

PBDEP		= app-client.pb.go
GWDEP		= app-client.pb.gw.go
CMDDEP		= $(CMDDIR)/app-client.cmd.go

COMMONDEPS	= $(PROTOS) $(PROTOC)
ALLDEPS		= $(PBDEP) $(GWDEP) $(CMDDEP)

build: $(PROTOS) $(ALLDEPS)

$(PBDEP): $(COMMONDEPS) $(GOMEX)
	protoc ${INCLUDE} --gomex_out=plugins=grpc+mex,${BUILTIN}:. $(PROTOS)

$(GWDEP): $(COMMONDEPS) $(GATEWAYGEN)
	protoc ${INCLUDE} --grpc-gateway_out=${BUILTIN}:. $(PROTOS)

$(CMDDEP): $(COMMONDEPS) $(CMDGEN)
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
