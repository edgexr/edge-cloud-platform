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
var TimestampComments = map[string]string{
	"seconds": "Time in seconds since epoch",
	"nanos":   "Added non-negative sub-second time in nanoseconds",
}
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
	"timestamp",
}
var LocAliasArgs = []string{}
var LocComments = map[string]string{
	"latitude":           "Latitude in WGS 84 coordinates",
	"longitude":          "Longitude in WGS 84 coordinates",
	"horizontalaccuracy": "Horizontal accuracy (radius in meters)",
	"verticalaccuracy":   "Vertical accuracy (meters)",
	"altitude":           "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"course":             "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"speed":              "Speed (IOS) / velocity (Android) (meters/sec)",
	"timestamp":          "Timestamp",
}
var LocSpecialArgs = map[string]string{}
var SampleRequiredArgs = []string{}
var SampleOptionalArgs = []string{
	"value",
	"timestamp",
	"tags",
}
var SampleAliasArgs = []string{}
var SampleComments = map[string]string{
	"value":     "Latency value",
	"timestamp": "Timestamp",
	"tags":      "_(optional)_ Vendor specific data",
}
var SampleSpecialArgs = map[string]string{
	"tags": "StringToString",
}
var StatisticsRequiredArgs = []string{}
var StatisticsOptionalArgs = []string{
	"avg",
	"min",
	"max",
	"stddev",
	"variance",
	"numsamples",
	"timestamp",
}
var StatisticsAliasArgs = []string{}
var StatisticsComments = map[string]string{
	"avg":        "Average",
	"min":        "Minimum",
	"max":        "Maximum",
	"stddev":     "Square root of unbiased variance",
	"variance":   "Unbiased variance",
	"numsamples": "Number of samples to create stats",
	"timestamp":  "Timestamp",
}
var StatisticsSpecialArgs = map[string]string{}
