# Makefile

GOPATH		= ../../../../..
GW		= $(shell go list -f '{{ .Dir }}' -m github.com/grpc-ecosystem/grpc-gateway)
APIS		= $(shell go list -f '{{ .Dir }}' -m github.com/gogo/googleapis)
GOGO		= $(shell go list -f '{{ .Dir }}' -m github.com/gogo/protobuf)
PROJECT		= $(shell go list -f '{{ .Dir }}' -m github.com/edgexr/edge-cloud-platform)
PROTOC		= $(shell which protoc)
GOMEX		= $(shell which protoc-gen-gomex)
NOTIFYGEN	= $(shell which protoc-gen-notify)
GATEWAYGEN	= $(shell which protoc-gen-grpc-gateway)
CMDGEN		= $(shell which protoc-gen-cmd)
TESTGEN		= $(shell which protoc-gen-test)
CTRLGEN		= $(shell which protoc-gen-controller)
CTRLTESTGEN	= $(shell which protoc-gen-controller-test)
MC2GEN		= $(shell which protoc-gen-mc2)
EDGEPROTOGENDIR	= $(PROJECT)/tools/edgeprotogen
PROTOGENDIR	= $(PROJECT)/tools/protogen
INCLUDE		= -I. -I${GW} -I${APIS} -I${GOGO} -I${GOPATH} -I${EDGEPROTOGENDIR} -I${PROTOGENDIR}
BUILTIN		= Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,Mgoogle/api/annotations.proto=github.com/gogo/googleapis/google/api,Mgoogle/protobuf/field_mask.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto

NOTIFYDIR	= ../../pkg/notify
CMDDIR		= ../../pkg/gencmd
TESTDIR		= ../../test/testutil
CTRLDIR		= ../../cmd/controller
ORMAPIDIR	= ../../api/ormapi
ORMDIR		= ../../pkg/mc/orm
CTRLCLIENTDIR	= ../../pkg/mc/ctrlclient
ORMTESTUTILDIR	= ../../pkg/mc/orm/testutil
MCCTLDIR	= ../../pkg/mcctl/ormctl

PROTOS		= $(shell ls *.proto)

# Make doesn't handle well the multiple-in, multiple-out way of building .proto files.
# Since all output files get built at once, we treat the first file as the output
# for timestamp checks.
# Also not all .proto files generate an output file, depending on the generator.
PBDEP		= alert.pb.go
GWDEP		= alert.pb.gw.go
NOTIFYDEP	= $(NOTIFYDIR)/alert.notify.go
CMDDEP		= $(CMDDIR)/alert.cmd.go
TESTDEP		= $(TESTDIR)/alert_testutil.go
CTRLTESTDEP	= $(CTRLDIR)/alertpolicy.auto_test.go
CTRLDEP		= $(CTRLDIR)/version.auto.go
ORMAPIDEP	= $(ORMAPIDIR)/alert.mc2.go
ORMDEP		= $(ORMDIR)/alert.mc2.go
ORMTESTDEP	= $(ORMDIR)/alert_mc2_test.go
CTRLCLIENTDEP	= $(CTRLCLIENTDIR)/alert.ctrl.go
ORMTESTUTILDEP	= $(ORMTESTUTILDIR)/alert_mc2_testutil.go
MCCTLDEP	= $(MCCTLDIR)/alert.mc2.go

COMMONDEPS	= $(PROTOS) $(PROTOC)
ALLDEPS		= $(PBDEP) $(GWDEP) $(NOTIFYDEP) $(CMDDEP) $(TESTDEP) $(CTRLTESTDEP) $(CTRLDEP) \
		$(ORMAPIDEP) $(ORMDEP) $(ORMTESTDEP) $(CTRLCLIENTDEP) $(ORMTESTUTILDEP) $(MCCTLDEP)

build: $(ALLDEPS)

$(PBDEP): $(COMMONDEPS) $(GOMEX)
	protoc ${INCLUDE} --gomex_out=plugins=grpc+mex,${BUILTIN}:. $(PROTOS)

$(GWDEP): $(COMMONDEPS) $(GATEWAYGEN)
	protoc ${INCLUDE} --grpc-gateway_out=${BUILTIN}:. $(PROTOS)

$(NOTIFYDEP): $(COMMONDEPS) $(NOTIFYGEN)
	protoc ${INCLUDE} --notify_out=${BUILTIN}:${NOTIFYDIR} $(PROTOS)

$(CMDDEP): $(COMMONDEPS) $(CMDGEN)
	protoc ${INCLUDE} --cmd_out=${BUILTIN}:${CMDDIR} $(PROTOS)

$(TESTDEP): $(COMMONDEPS) $(TESTGEN)
	protoc ${INCLUDE} --test_out=${BUILTIN}:${TESTDIR} $(PROTOS)

$(CTRLTESTDEP): $(COMMONDEPS) $(CTRLTESTGEN)
	protoc ${INCLUDE} --controller-test_out=${BUILTIN}:${CTRLDIR} $(PROTOS)

$(CTRLDEP): $(COMMONDEPS) $(CTRLGEN)
	protoc ${INCLUDE} --controller_out=${BUILTIN}:${CTRLDIR} version.proto

$(ORMAPIDEP): $(COMMONDEPS) $(MC2GEN)
	protoc ${INCLUDE} --mc2_out=${BUILTIN},genapi,pkg=ormapi:${ORMAPIDIR} $(PROTOS)

$(ORMDEP): $(COMMONDEPS) $(MC2GEN)
	protoc ${INCLUDE} --mc2_out=${BUILTIN}:${ORMDIR} $(PROTOS)

$(ORMTESTDEP): $(COMMONDEPS) $(MC2GEN)
	protoc ${INCLUDE} --mc2_out=${BUILTIN},gentest,suffix=_mc2_test.go:${ORMDIR} $(PROTOS)

$(CTRLCLIENTDEP): $(COMMONDEPS) $(MC2GEN)
	protoc ${INCLUDE} --mc2_out=${BUILTIN},genctrlclient,pkg=ctrlclient,suffix=.ctrl.go:${CTRLCLIENTDIR} $(PROTOS)

$(ORMTESTUTILDEP): $(COMMONDEPS) $(MC2GEN)
	protoc ${INCLUDE} --mc2_out=${BUILTIN},gentestutil,pkg=testutil,suffix=_mc2_testutil.go:${ORMTESTUTILDIR} $(PROTOS)

$(MCCTLDEP): $(COMMONDEPS) $(MC2GEN)
	protoc ${INCLUDE} --mc2_out=${BUILTIN},genctl,pkg=ormctl:${MCCTLDIR} $(PROTOS)

doc: build
	protoc ${INCLUDE} --doc_out=./doc --doc_opt=html,index.html *.proto
	protoc ${INCLUDE} --doc_out=./doc --doc_opt=markdown,README.md *.proto
	#swagger annotations for REST APIs
	protoc ${INCLUDE} --swagger_out=logtostderr=true,allow_merge=true:./doc  *.proto

external-doc: build
	mkdir -p ./external-doc
	protoc ${INCLUDE} --swagger_out=logtostderr=true,allow_merge=true,config_file=swagger_config.yaml:./external-doc  *.proto
