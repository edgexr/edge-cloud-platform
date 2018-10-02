// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: common.proto

package gencmd

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
var LivenessStrings = []string{
	"LivenessUnknown",
	"LivenessStatic",
	"LivenessDynamic",
}

var IpSupportStrings = []string{
	"IpSupportUnknown",
	"IpSupportStatic",
	"IpSupportDynamic",
}

var IpAccessStrings = []string{
	"IpAccessUnknown",
	"IpAccessDedicated",
	"IpAccessDedicatedOrShared",
	"IpAccessShared",
}

var TrackedStateStrings = []string{
	"TrackedStateUnknown",
	"NotPresent",
	"CreateRequested",
	"Creating",
	"CreateError",
	"Ready",
	"UpdateRequested",
	"Updating",
	"UpdateError",
	"DeleteRequested",
	"Deleting",
	"DeleteError",
}

var CRMOverrideStrings = []string{
	"NoOverride",
	"IgnoreCRMErrors",
	"IgnoreCRM",
	"IgnoreTransientState",
}

func init() {
}
