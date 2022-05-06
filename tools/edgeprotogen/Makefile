# Makefile

EDGEPROTOGENDIR	= ${GOPATH}/src/github.com/edgexr/edge-proto/edgeprotogen
PROTOS		= edgeprotogen.proto

build: $(PROTOS)
	protoc -I. --gogofast_out=Mgoogle/protobuf/descriptor.proto=github.com/gogo/protobuf/protoc-gen-gogo/descriptor:. *.proto

$(PROTOS):
	ln -sf ${EDGEPROTOGENDIR}/$@ $@
