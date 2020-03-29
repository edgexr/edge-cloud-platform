// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: device.proto

package gencmd

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "strings"
import "github.com/spf13/cobra"
import "context"
import "io"
import "github.com/mobiledgex/edge-cloud/cli"
import "google.golang.org/grpc/status"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"
import _ "github.com/gogo/protobuf/types"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
func DeviceHideTags(in *edgeproto.Device) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.NotifyId = 0
	}
}

var DeviceApiCmd edgeproto.DeviceApiClient

var InjectDeviceCmd = &cli.Command{
	Use:          "InjectDevice",
	RequiredArgs: strings.Join(DeviceRequiredArgs, " "),
	OptionalArgs: strings.Join(DeviceOptionalArgs, " "),
	AliasArgs:    strings.Join(DeviceAliasArgs, " "),
	SpecialArgs:  &DeviceSpecialArgs,
	Comments:     DeviceComments,
	ReqData:      &edgeproto.Device{},
	ReplyData:    &edgeproto.Result{},
	Run:          runInjectDevice,
}

func runInjectDevice(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.Device)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return InjectDevice(c, obj)
}

func InjectDevice(c *cli.Command, in *edgeproto.Device) error {
	if DeviceApiCmd == nil {
		return fmt.Errorf("DeviceApi client not initialized")
	}
	ctx := context.Background()
	obj, err := DeviceApiCmd.InjectDevice(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("InjectDevice failed: %s", errstr)
	}
	c.WriteOutput(obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func InjectDevices(c *cli.Command, data []edgeproto.Device, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("InjectDevice %v\n", data[ii])
		myerr := InjectDevice(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowDeviceCmd = &cli.Command{
	Use:          "ShowDevice",
	OptionalArgs: strings.Join(append(DeviceRequiredArgs, DeviceOptionalArgs...), " "),
	AliasArgs:    strings.Join(DeviceAliasArgs, " "),
	SpecialArgs:  &DeviceSpecialArgs,
	Comments:     DeviceComments,
	ReqData:      &edgeproto.Device{},
	ReplyData:    &edgeproto.Device{},
	Run:          runShowDevice,
}

func runShowDevice(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.Device)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowDevice(c, obj)
}

func ShowDevice(c *cli.Command, in *edgeproto.Device) error {
	if DeviceApiCmd == nil {
		return fmt.Errorf("DeviceApi client not initialized")
	}
	ctx := context.Background()
	stream, err := DeviceApiCmd.ShowDevice(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowDevice failed: %s", errstr)
	}

	objs := make([]*edgeproto.Device, 0)
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			errstr := err.Error()
			st, ok := status.FromError(err)
			if ok {
				errstr = st.Message()
			}
			return fmt.Errorf("ShowDevice recv failed: %s", errstr)
		}
		DeviceHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowDevices(c *cli.Command, data []edgeproto.Device, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowDevice %v\n", data[ii])
		myerr := ShowDevice(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var EvictDeviceCmd = &cli.Command{
	Use:          "EvictDevice",
	RequiredArgs: strings.Join(DeviceRequiredArgs, " "),
	OptionalArgs: strings.Join(DeviceOptionalArgs, " "),
	AliasArgs:    strings.Join(DeviceAliasArgs, " "),
	SpecialArgs:  &DeviceSpecialArgs,
	Comments:     DeviceComments,
	ReqData:      &edgeproto.Device{},
	ReplyData:    &edgeproto.Result{},
	Run:          runEvictDevice,
}

func runEvictDevice(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.Device)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return EvictDevice(c, obj)
}

func EvictDevice(c *cli.Command, in *edgeproto.Device) error {
	if DeviceApiCmd == nil {
		return fmt.Errorf("DeviceApi client not initialized")
	}
	ctx := context.Background()
	obj, err := DeviceApiCmd.EvictDevice(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("EvictDevice failed: %s", errstr)
	}
	c.WriteOutput(obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func EvictDevices(c *cli.Command, data []edgeproto.Device, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("EvictDevice %v\n", data[ii])
		myerr := EvictDevice(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowDeviceReportCmd = &cli.Command{
	Use:          "ShowDeviceReport",
	OptionalArgs: strings.Join(append(DeviceReportRequiredArgs, DeviceReportOptionalArgs...), " "),
	AliasArgs:    strings.Join(DeviceReportAliasArgs, " "),
	SpecialArgs:  &DeviceReportSpecialArgs,
	Comments:     DeviceReportComments,
	ReqData:      &edgeproto.DeviceReport{},
	ReplyData:    &edgeproto.Device{},
	Run:          runShowDeviceReport,
}

func runShowDeviceReport(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.DeviceReport)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowDeviceReport(c, obj)
}

func ShowDeviceReport(c *cli.Command, in *edgeproto.DeviceReport) error {
	if DeviceApiCmd == nil {
		return fmt.Errorf("DeviceApi client not initialized")
	}
	ctx := context.Background()
	stream, err := DeviceApiCmd.ShowDeviceReport(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowDeviceReport failed: %s", errstr)
	}

	objs := make([]*edgeproto.Device, 0)
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			errstr := err.Error()
			st, ok := status.FromError(err)
			if ok {
				errstr = st.Message()
			}
			return fmt.Errorf("ShowDeviceReport recv failed: %s", errstr)
		}
		DeviceHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowDeviceReports(c *cli.Command, data []edgeproto.DeviceReport, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowDeviceReport %v\n", data[ii])
		myerr := ShowDeviceReport(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeviceApiCmds = []*cobra.Command{
	InjectDeviceCmd.GenCmd(),
	ShowDeviceCmd.GenCmd(),
	EvictDeviceCmd.GenCmd(),
	ShowDeviceReportCmd.GenCmd(),
}

var DeviceReportRequiredArgs = []string{
	"key.uniqueidtype",
	"key.uniqueid",
}
var DeviceReportOptionalArgs = []string{
	"begin.seconds",
	"begin.nanos",
	"end.seconds",
	"end.nanos",
}
var DeviceReportAliasArgs = []string{}
var DeviceReportComments = map[string]string{
	"key.uniqueidtype": "Type of unique ID provided by the client",
	"key.uniqueid":     "Unique identification of the client device or user. May be overridden by the server.",
	"begin.seconds":    "Represents seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive.",
	"begin.nanos":      "Non-negative fractions of a second at nanosecond resolution. Negative second values with fractions must still have non-negative nanos values that count forward in time. Must be from 0 to 999,999,999 inclusive.",
	"end.seconds":      "Represents seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive.",
	"end.nanos":        "Non-negative fractions of a second at nanosecond resolution. Negative second values with fractions must still have non-negative nanos values that count forward in time. Must be from 0 to 999,999,999 inclusive.",
}
var DeviceReportSpecialArgs = map[string]string{}
var DeviceKeyRequiredArgs = []string{}
var DeviceKeyOptionalArgs = []string{
	"uniqueidtype",
	"uniqueid",
}
var DeviceKeyAliasArgs = []string{}
var DeviceKeyComments = map[string]string{
	"uniqueidtype": "Type of unique ID provided by the client",
	"uniqueid":     "Unique identification of the client device or user. May be overridden by the server.",
}
var DeviceKeySpecialArgs = map[string]string{}
var DeviceRequiredArgs = []string{
	"key.uniqueidtype",
	"key.uniqueid",
}
var DeviceOptionalArgs = []string{
	"firstseen.seconds",
	"firstseen.nanos",
	"lastseen.seconds",
	"lastseen.nanos",
	"notifyid",
}
var DeviceAliasArgs = []string{}
var DeviceComments = map[string]string{
	"key.uniqueidtype":  "Type of unique ID provided by the client",
	"key.uniqueid":      "Unique identification of the client device or user. May be overridden by the server.",
	"firstseen.seconds": "Represents seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive.",
	"firstseen.nanos":   "Non-negative fractions of a second at nanosecond resolution. Negative second values with fractions must still have non-negative nanos values that count forward in time. Must be from 0 to 999,999,999 inclusive.",
	"lastseen.seconds":  "Represents seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive.",
	"lastseen.nanos":    "Non-negative fractions of a second at nanosecond resolution. Negative second values with fractions must still have non-negative nanos values that count forward in time. Must be from 0 to 999,999,999 inclusive.",
	"notifyid":          "Id of client assigned by server (internal use only)",
}
var DeviceSpecialArgs = map[string]string{
	"fields": "StringArray",
}
