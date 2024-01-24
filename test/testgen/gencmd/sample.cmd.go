// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: sample.proto

package gencmd

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	testgen "github.com/edgexr/edge-cloud-platform/test/testgen"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	math "math"
	"strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
func TestGenHideTags(in *testgen.TestGen) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	for i0 := 0; i0 < len(in.RepeatedMsg); i0++ {
	}
	for i0 := 0; i0 < len(in.RepeatedMsgNonnull); i0++ {
	}
	for i0 := 0; i0 < len(in.RepeatedFields); i0++ {
	}
	for i0 := 0; i0 < len(in.RepeatedFieldsNonnull); i0++ {
	}
	for i0 := 0; i0 < len(in.RepeatedInnerMsg); i0++ {
	}
	for i0 := 0; i0 < len(in.RepeatedInnerMsgNonnull); i0++ {
	}
	for i0 := 0; i0 < len(in.RepeatedLoc); i0++ {
	}
	for i0 := 0; i0 < len(in.RepeatedLocNonnull); i0++ {
	}
	if _, found := tags["nocmp"]; found {
		in.Unused = ""
	}
}

var TestApiCmd testgen.TestApiClient

var RequestCmd = &cli.Command{
	Use:          "Request",
	RequiredArgs: strings.Join(TestGenRequiredArgs, " "),
	OptionalArgs: strings.Join(TestGenOptionalArgs, " "),
	AliasArgs:    strings.Join(TestGenAliasArgs, " "),
	SpecialArgs:  &TestGenSpecialArgs,
	Comments:     TestGenComments,
	ReqData:      &testgen.TestGen{},
	ReplyData:    &testgen.TestGen{},
	Run:          runRequest,
}

func runRequest(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*testgen.TestGen)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return Request(c, obj)
}

func Request(c *cli.Command, in *testgen.TestGen) error {
	if TestApiCmd == nil {
		return fmt.Errorf("TestApi client not initialized")
	}
	ctx := context.Background()
	obj, err := TestApiCmd.Request(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("Request failed: %s", errstr)
	}
	TestGenHideTags(obj)
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func Requests(c *cli.Command, data []testgen.TestGen, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("Request %v\n", data[ii])
		myerr := Request(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var TestApiCmds = []*cobra.Command{
	RequestCmd.GenCmd(),
}

var NestedMessageRequiredArgs = []string{}
var NestedMessageOptionalArgs = []string{
	"name",
}
var NestedMessageAliasArgs = []string{}
var NestedMessageComments = map[string]string{}
var NestedMessageSpecialArgs = map[string]string{}
var IncludeMessageRequiredArgs = []string{}
var IncludeMessageOptionalArgs = []string{
	"name",
	"id",
	"nestedmsg.name",
}
var IncludeMessageAliasArgs = []string{}
var IncludeMessageComments = map[string]string{}
var IncludeMessageSpecialArgs = map[string]string{}
var IncludeFieldsRequiredArgs = []string{}
var IncludeFieldsOptionalArgs = []string{
	"name",
}
var IncludeFieldsAliasArgs = []string{}
var IncludeFieldsComments = map[string]string{}
var IncludeFieldsSpecialArgs = map[string]string{}
var TestGenRequiredArgs = []string{}
var TestGenOptionalArgs = []string{
	"name",
	"db",
	"fl",
	"i32",
	"i64",
	"u32",
	"u64",
	"s32",
	"s64",
	"f32",
	"f64",
	"sf32",
	"sf64",
	"bb",
	"outeren",
	"inneren",
	"innermsg.url",
	"innermsg.id",
	"innermsgnonnull.url",
	"innermsgnonnull.id",
	"includemsg.name",
	"includemsg.id",
	"includemsg.nestedmsg.name",
	"includemsgnonnull.name",
	"includemsgnonnull.id",
	"includemsgnonnull.nestedmsg.name",
	"includefields.fields",
	"includefields.name",
	"includefieldsnonnull.fields",
	"includefieldsnonnull.name",
	"loc.latitude",
	"loc.longitude",
	"loc.horizontalaccuracy",
	"loc.verticalaccuracy",
	"loc.altitude",
	"loc.course",
	"loc.speed",
	"loc.timestamp",
	"locnonnull.latitude",
	"locnonnull.longitude",
	"locnonnull.horizontalaccuracy",
	"locnonnull.verticalaccuracy",
	"locnonnull.altitude",
	"locnonnull.course",
	"locnonnull.speed",
	"locnonnull.timestamp",
	"repeatedint",
	"ip",
	"names",
	"repeatedmsg:#.name",
	"repeatedmsg:#.id",
	"repeatedmsg:#.nestedmsg.name",
	"repeatedmsgnonnull:#.name",
	"repeatedmsgnonnull:#.id",
	"repeatedmsgnonnull:#.nestedmsg.name",
	"repeatedfields:#.fields",
	"repeatedfields:#.name",
	"repeatedfieldsnonnull:#.fields",
	"repeatedfieldsnonnull:#.name",
	"repeatedinnermsg:#.url",
	"repeatedinnermsg:#.id",
	"repeatedinnermsgnonnull:#.url",
	"repeatedinnermsgnonnull:#.id",
	"repeatedloc:#.latitude",
	"repeatedloc:#.longitude",
	"repeatedloc:#.horizontalaccuracy",
	"repeatedloc:#.verticalaccuracy",
	"repeatedloc:#.altitude",
	"repeatedloc:#.course",
	"repeatedloc:#.speed",
	"repeatedloc:#.timestamp",
	"repeatedlocnonnull:#.latitude",
	"repeatedlocnonnull:#.longitude",
	"repeatedlocnonnull:#.horizontalaccuracy",
	"repeatedlocnonnull:#.verticalaccuracy",
	"repeatedlocnonnull:#.altitude",
	"repeatedlocnonnull:#.course",
	"repeatedlocnonnull:#.speed",
	"repeatedlocnonnull:#.timestamp",
	"unused",
}
var TestGenAliasArgs = []string{}
var TestGenComments = map[string]string{
	"outeren":                                 ", one of 0, 1, 2, 3",
	"inneren":                                 ", one of 0, 1, 2, 3",
	"loc.latitude":                            "Latitude in WGS 84 coordinates",
	"loc.longitude":                           "Longitude in WGS 84 coordinates",
	"loc.horizontalaccuracy":                  "Horizontal accuracy (radius in meters)",
	"loc.verticalaccuracy":                    "Vertical accuracy (meters)",
	"loc.altitude":                            "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"loc.course":                              "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"loc.speed":                               "Speed (IOS) / velocity (Android) (meters/sec)",
	"loc.timestamp":                           "Timestamp",
	"locnonnull.latitude":                     "Latitude in WGS 84 coordinates",
	"locnonnull.longitude":                    "Longitude in WGS 84 coordinates",
	"locnonnull.horizontalaccuracy":           "Horizontal accuracy (radius in meters)",
	"locnonnull.verticalaccuracy":             "Vertical accuracy (meters)",
	"locnonnull.altitude":                     "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"locnonnull.course":                       "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"locnonnull.speed":                        "Speed (IOS) / velocity (Android) (meters/sec)",
	"locnonnull.timestamp":                    "Timestamp",
	"repeatedloc:#.latitude":                  "Latitude in WGS 84 coordinates",
	"repeatedloc:#.longitude":                 "Longitude in WGS 84 coordinates",
	"repeatedloc:#.horizontalaccuracy":        "Horizontal accuracy (radius in meters)",
	"repeatedloc:#.verticalaccuracy":          "Vertical accuracy (meters)",
	"repeatedloc:#.altitude":                  "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"repeatedloc:#.course":                    "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"repeatedloc:#.speed":                     "Speed (IOS) / velocity (Android) (meters/sec)",
	"repeatedloc:#.timestamp":                 "Timestamp",
	"repeatedlocnonnull:#.latitude":           "Latitude in WGS 84 coordinates",
	"repeatedlocnonnull:#.longitude":          "Longitude in WGS 84 coordinates",
	"repeatedlocnonnull:#.horizontalaccuracy": "Horizontal accuracy (radius in meters)",
	"repeatedlocnonnull:#.verticalaccuracy":   "Vertical accuracy (meters)",
	"repeatedlocnonnull:#.altitude":           "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"repeatedlocnonnull:#.course":             "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"repeatedlocnonnull:#.speed":              "Speed (IOS) / velocity (Android) (meters/sec)",
	"repeatedlocnonnull:#.timestamp":          "Timestamp",
	"unused":                                  "xxx win import of strings. xxx",
}
var TestGenSpecialArgs = map[string]string{
	"fields": "StringArray",
	"names":  "StringArray",
}
var InnerMessageRequiredArgs = []string{}
var InnerMessageOptionalArgs = []string{
	"url",
	"id",
}
var InnerMessageAliasArgs = []string{}
var InnerMessageComments = map[string]string{}
var InnerMessageSpecialArgs = map[string]string{}
