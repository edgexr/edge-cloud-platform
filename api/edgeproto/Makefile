# Makefile

GOPATH		= ../../../../..
PROTODEPS	:= $(shell go list -f '{{ .Dir }}' -m \
	github.com/grpc-ecosystem/grpc-gateway \
	github.com/gogo/googleapis \
	github.com/gogo/protobuf \
	github.com/edgexr/edge-cloud-platform)
GW		:= $(word 1,$(PROTODEPS))
APIS		:= $(word 2,$(PROTODEPS))
GOGO		:= $(word 3,$(PROTODEPS))
PROJECT		:= $(word 4,$(PROTODEPS))
EDGEPROTOGENDIR	:= $(PROJECT)/tools/edgeprotogen
PROTOGENDIR	:= $(PROJECT)/tools/protogen
INCLUDE		:= -I. -I${GW} -I${APIS} -I${GOGO} -I${GOPATH} -I${EDGEPROTOGENDIR} -I${PROTOGENDIR}
BUILTIN		= Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,Mgoogle/api/annotations.proto=github.com/gogo/googleapis/google/api,Mgoogle/protobuf/field_mask.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto

NOTIFYDIR	= ../../pkg/notify
CMDDIR		= ../../pkg/gencmd
TESTDIR		= ../../test/testutil
CTRLDIR		= ../../cmd/controller
REDISAPIDIR = ../../pkg/rediscache

PROTOS		= *.proto

build:
	protoc ${INCLUDE} --gomex_out=plugins=grpc+mex,${BUILTIN}:. $(PROTOS)
	protoc ${INCLUDE} --grpc-gateway_out=${BUILTIN}:. $(PROTOS)
	protoc ${INCLUDE} --notify_out=${BUILTIN}:${NOTIFYDIR} $(PROTOS)
	protoc ${INCLUDE} --cmd_out=${BUILTIN}:${CMDDIR} $(PROTOS)
	protoc ${INCLUDE} --redisapi_out=${BUILTIN}:${REDISAPIDIR} $(PROTOS)
	protoc ${INCLUDE} --test_out=${BUILTIN}:${TESTDIR} $(PROTOS)
	protoc ${INCLUDE} --controller-test_out=${BUILTIN}:${CTRLDIR} $(PROTOS)
	protoc ${INCLUDE} --controller_out=${BUILTIN}:${CTRLDIR} version.proto
