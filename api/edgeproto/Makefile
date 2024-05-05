# Makefile

REPO	:= github.com/edgexr/edge-cloud-platform

# This makefile may be included in other Makefiles, to ensure
# the correct deps are used, we need to use the correct directory
# for the next go list call.
REPODIR		?= $(shell go list -f '{{ .Dir }}' -m ${REPO})

GOPATH		= ../../../../..
PROTODEPS	:= $(shell cd ${REPODIR} && go list -f '{{ .Dir }}' -m \
	github.com/grpc-ecosystem/grpc-gateway \
	github.com/gogo/googleapis \
	github.com/gogo/protobuf \
	github.com/edgexr/edge-proto)
GW		:= $(word 1,$(PROTODEPS))
APIS		:= $(word 2,$(PROTODEPS))
GOGO		:= $(word 3,$(PROTODEPS))
EDGEPROTO	:= $(word 4,$(PROTODEPS))
EDGEPROTOGENDIR	:= $(EDGEPROTO)/edgeprotogen
PROTOGENDIR	:= $(REPODIR)/tools/protogen
INCLUDE		:= -I. -I${GW} -I${APIS} -I${GOGO} -I${GOPATH} -I${EDGEPROTOGENDIR} -I${PROTOGENDIR} -I${REPODIR}

# The M option specifies the package name for DME protos because they
# live in a different repo and don't have a go_package option
# tailored to this repo.
DMEPROTOS	:= $(shell cd ${EDGEPROTO}/dme && ls *.proto)
DMEREFS		:= $(patsubst %,Mapi/distributed_match_engine/%=$(REPO)/api/distributed_match_engine,${DMEPROTOS})
# convert to comma separated list
null	:=
space	:= $(null) #
comma	:= ,
MDME	:= $(subst $(space),$(comma),$(strip $(DMEREFS)))

PGENPROTOS	:= $(shell cd ${PROTOGENDIR} && ls *.proto)
PGENREFS	:= $(patsubst %,Mtools/protogen/%=$(REPO)/tools/protogen,${PGENPROTOS})
MPGEN		:= $(subst $(space),$(comma),$(strip $(PGENREFS)))

BUILTIN		= Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,Mgoogle/api/annotations.proto=github.com/gogo/googleapis/google/api,Mgoogle/protobuf/field_mask.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto,${MDME},${MPGEN}

NOTIFYDIR	= ../../pkg/notify
CMDDIR		= ../../pkg/gencmd
TESTDIR		= ../../test/testutil
CTRLDIR		= ../../pkg/controller
REDISAPIDIR = ../../pkg/rediscache

PROTOS		= *.proto

OPTS		:= ${BUILTIN},srcimport=$(REPO)/api/edgeproto

build:
	protoc ${INCLUDE} --gomex_out=plugins=grpc+mex,${BUILTIN}:. $(PROTOS)
	protoc ${INCLUDE} --grpc-gateway_out=${BUILTIN}:. $(PROTOS)
	protoc ${INCLUDE} --notify_out=${OPTS}:${NOTIFYDIR} $(PROTOS)
	protoc ${INCLUDE} --cmd_out=${OPTS}:${CMDDIR} $(PROTOS)
	protoc ${INCLUDE} --redisapi_out=${OPTS}:${REDISAPIDIR} $(PROTOS)
	protoc ${INCLUDE} --test_out=${OPTS}:${TESTDIR} $(PROTOS)
	protoc ${INCLUDE} --controller-test_out=${OPTS}:${CTRLDIR} $(PROTOS)
	protoc ${INCLUDE} --controller_out=${OPTS}:${CTRLDIR} version.proto
