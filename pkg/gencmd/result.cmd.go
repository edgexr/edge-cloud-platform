// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: result.proto

package gencmd

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
var ResultRequiredArgs = []string{}
var ResultOptionalArgs = []string{
	"message",
	"code",
}
var ResultAliasArgs = []string{}
var ResultComments = map[string]string{
	"message": "Message, may be success or failure message",
	"code":    "Error code, 0 indicates success, non-zero indicates failure (not implemented)",
}
var ResultSpecialArgs = map[string]string{}