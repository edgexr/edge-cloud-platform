# Makefile

#PROTOC		= $(shell which protoc)
#GOGOFAST	= $(shell which protoc-gen-gogofast)

build:
	protoc -I. --gogofast_out=Mgoogle/protobuf/descriptor.proto=github.com/gogo/protobuf/protoc-gen-gogo/descriptor:. *.proto

