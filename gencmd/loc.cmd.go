// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: loc.proto

package gencmd

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
var TimestampRequiredArgs = []string{}
var TimestampOptionalArgs = []string{
	"seconds",
	"nanos",
}
var TimestampAliasArgs = []string{}
var TimestampComments = map[string]string{}
var TimestampSpecialArgs = map[string]string{}
var LocRequiredArgs = []string{}
var LocOptionalArgs = []string{
	"latitude",
	"longitude",
	"horizontalaccuracy",
	"verticalaccuracy",
	"altitude",
	"course",
	"speed",
	"timestamp.seconds",
	"timestamp.nanos",
}
var LocAliasArgs = []string{}
var LocComments = map[string]string{
	"latitude":           "latitude in WGS 84 coordinates",
	"longitude":          "longitude in WGS 84 coordinates",
	"horizontalaccuracy": "horizontal accuracy (radius in meters)",
	"verticalaccuracy":   "vertical accuracy (meters)",
	"altitude":           "On android only lat and long are guaranteed to be supplied altitude in meters",
	"course":             "course (IOS) / bearing (Android) (degrees east relative to true north)",
	"speed":              "speed (IOS) / velocity (Android) (meters/sec)",
}
var LocSpecialArgs = map[string]string{}
