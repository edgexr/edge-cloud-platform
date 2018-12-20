// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: loc.proto

package gencmd

import distributed_match_engine "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import "strings"
import "strconv"
import "os"
import "text/tabwriter"
import "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/cmdsup"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
func TimestampSlicer(in *distributed_match_engine.Timestamp) []string {
	s := make([]string, 0, 2)
	s = append(s, strconv.FormatUint(uint64(in.Seconds), 10))
	s = append(s, strconv.FormatUint(uint64(in.Nanos), 10))
	return s
}

func TimestampHeaderSlicer() []string {
	s := make([]string, 0, 2)
	s = append(s, "Seconds")
	s = append(s, "Nanos")
	return s
}

func TimestampWriteOutputArray(objs []*distributed_match_engine.Timestamp) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(TimestampHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(TimestampSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func TimestampWriteOutputOne(obj *distributed_match_engine.Timestamp) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(TimestampHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(TimestampSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func LocSlicer(in *distributed_match_engine.Loc) []string {
	s := make([]string, 0, 8)
	s = append(s, strconv.FormatFloat(float64(in.Latitude), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Longitude), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.HorizontalAccuracy), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.VerticalAccuracy), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Altitude), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Course), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Speed), 'e', -1, 32))
	if in.Timestamp == nil {
		in.Timestamp = &distributed_match_engine.Timestamp{}
	}
	s = append(s, strconv.FormatUint(uint64(in.Timestamp.Seconds), 10))
	s = append(s, strconv.FormatUint(uint64(in.Timestamp.Nanos), 10))
	return s
}

func LocHeaderSlicer() []string {
	s := make([]string, 0, 8)
	s = append(s, "Latitude")
	s = append(s, "Longitude")
	s = append(s, "HorizontalAccuracy")
	s = append(s, "VerticalAccuracy")
	s = append(s, "Altitude")
	s = append(s, "Course")
	s = append(s, "Speed")
	s = append(s, "Timestamp-Seconds")
	s = append(s, "Timestamp-Nanos")
	return s
}

func LocWriteOutputArray(objs []*distributed_match_engine.Loc) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(LocHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(LocSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func LocWriteOutputOne(obj *distributed_match_engine.Loc) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(LocHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(LocSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func init() {
}
