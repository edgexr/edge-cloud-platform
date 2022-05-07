# Makefile

GOPATH		= ../../../../..
GOGO		= $(shell go list -f '{{ .Dir }}' -m github.com/gogo/protobuf)
PROJECT		= $(shell go list -f '{{ .Dir }}' -m github.com/edgexr/edge-cloud-platform)
PROTOC		= $(shell which protoc)
GOMEX		= $(shell which protoc-gen-gomex)
TESTGEN		= $(shell which protoc-gen-test)
GATEWAYGEN	= $(shell which protoc-gen-grpc-gateway)
CMDGEN		= $(shell which protoc-gen-cmd)
EDGEPROTOGENDIR	= $(PROJECT)/tools/edgeprotogen
PROTOGENDIR	= $(PROJECT)/tools/protogen
INCLUDE		= -I. -I${GOGO} -I${GOPATH} -I${EDGEPROTOGENDIR} -I${PROTOGENDIR}
BUILTIN		= Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,Mgoogle/api/annotations.proto=github.com/gogo/googleapis/google/api,Mgoogle/protobuf/field_mask.proto=github.com/gogo/protobuf/types,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto

TESTDIR		= ./testutil
CMDDIR		= ./gencmd

PROTOS		= $(shell ls *.proto)

PBDEP		= sample.pb.go
GWDEP		= sample.pb.gw.go
TESTDEP		= $(TESTDIR)/sample_testutil.go
CMDDEP		= $(CMDDIR)/sample.cmd.go

COMMONDEPS	= $(PROTOS) $(PROTOC)
ALLDEPS		= $(PBDEP) $(GWDEP) $(TESTDEP) $(CMDDEP)

build: $(ALLDEPS)

$(PBDEP): $(COMMONDEPS) $(GOMEX)
	protoc ${INCLUDE} --gomex_out=plugins=grpc+mex,${BUILTIN}:. $(PROTOS)

$(GWDEP): $(COMMONDEPS) $(GATEWAYGEN)
	protoc ${INCLUDE} --grpc-gateway_out=${BUILTIN}:. $(PROTOS)

$(TESTDEP): $(COMMONDEPS) $(TESTGEN)
	protoc ${INCLUDE} --test_out=${BUILTIN}:${TESTDIR} $(PROTOS)

$(CMDDEP): $(COMMONDEPS) $(CMDGEN)
	protoc ${INCLUDE} --cmd_out=${BUILTIN}:${CMDDIR} $(PROTOS)
