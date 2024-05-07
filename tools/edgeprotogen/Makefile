# Makefile

EDGEPROTO	:= $(shell go list -f '{{ .Dir }}' -m \
	github.com/edgexr/edge-proto)

EDGEPROTOGENDIR	= ${EDGEPROTO}/edgeprotogen
PROTOS		= edgeprotogen.proto

build:
	protoc -I${EDGEPROTOGENDIR} --gogofast_out=Mgoogle/protobuf/descriptor.proto=github.com/gogo/protobuf/protoc-gen-gogo/descriptor:. $(PROTOS)
