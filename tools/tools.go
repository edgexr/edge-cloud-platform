// +build tools

package tools

import (
	_ "github.com/gogo/protobuf/protoc-gen-gogofast"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger"
)
