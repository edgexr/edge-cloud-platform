# Makefile

REPO	:= github.com/edgexr/edge-cloud-platform

GOPATH		= ../../../../..
PROTODEPS	:= $(shell go list -f '{{ .Dir }}' -m \
	github.com/gogo/protobuf \
	github.com/edgexr/edge-proto \
	${REPO})
GOGO		:= $(word 1,$(PROTODEPS))
EDGEPROTO	:= $(word 2,$(PROTODEPS))
PROJECT		:= $(word 3,$(PROTODEPS))
PROTOC		= $(shell which protoc)
GOMEX		= $(shell which protoc-gen-gomex)
TESTGEN		= $(shell which protoc-gen-test)
GATEWAYGEN	= $(shell which protoc-gen-grpc-gateway)
CMDGEN		= $(shell which protoc-gen-cmd)
EDGEPROTOGENDIR	= $(PROJECT)/tools/edgeprotogen
PROTOGENDIR	= $(PROJECT)/tools/protogen
INCLUDE		= -I. -I${GOGO} -I${GOPATH} -I${EDGEPROTOGENDIR} -I${PROTOGENDIR} -I${PROJECT}

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

BUILTIN		= Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,Mgoogle/api/annotations.proto=github.com/gogo/googleapis/google/api,Mgoogle/protobuf/field_mask.proto=github.com/gogo/protobuf/types,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto,${MDME},${MPGEN}

TESTDIR		= ./testutil
CMDDIR		= ./gencmd

PROTOS		= $(shell ls *.proto)

PBDEP		= sample.pb.go
GWDEP		= sample.pb.gw.go
TESTDEP		= $(TESTDIR)/sample_testutil.go
CMDDEP		= $(CMDDIR)/sample.cmd.go

COMMONDEPS	= $(PROTOS) $(PROTOC)
ALLDEPS		= $(PBDEP) $(GWDEP) $(TESTDEP) $(CMDDEP)

OPTS		:= ${BUILTIN},srcimport=$(REPO)/test/testgen

build: $(ALLDEPS)

$(PBDEP): $(COMMONDEPS) $(GOMEX)
	protoc ${INCLUDE} --gomex_out=plugins=grpc+mex,${BUILTIN}:. $(PROTOS)

$(GWDEP): $(COMMONDEPS) $(GATEWAYGEN)
	protoc ${INCLUDE} --grpc-gateway_out=${BUILTIN}:. $(PROTOS)

$(TESTDEP): $(COMMONDEPS) $(TESTGEN)
	protoc ${INCLUDE} --test_out=${OPTS}:${TESTDIR} $(PROTOS)

$(CMDDEP): $(COMMONDEPS) $(CMDGEN)
	protoc ${INCLUDE} --cmd_out=${OPTS}:${CMDDIR} $(PROTOS)
