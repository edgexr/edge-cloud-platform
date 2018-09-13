// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app_inst.proto

package gencmd

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import google_protobuf "github.com/gogo/protobuf/types"
import "strings"
import "time"
import "strconv"
import "github.com/spf13/cobra"
import "context"
import "os"
import "io"
import "text/tabwriter"
import "github.com/spf13/pflag"
import "errors"
import "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/cmdsup"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
var AppInstApiCmd edgeproto.AppInstApiClient
var AppInstInfoApiCmd edgeproto.AppInstInfoApiClient
var AppInstMetricsApiCmd edgeproto.AppInstMetricsApiClient
var AppInstIn edgeproto.AppInst
var AppInstFlagSet = pflag.NewFlagSet("AppInst", pflag.ExitOnError)
var AppInstNoConfigFlagSet = pflag.NewFlagSet("AppInstNoConfig", pflag.ExitOnError)
var AppInstInLiveness string
var AppInstInImageType string
var AppInstInMappedPortsProto string
var AppInstInAccessLayer string
var AppInstInState string
var AppInstInfoIn edgeproto.AppInstInfo
var AppInstInfoFlagSet = pflag.NewFlagSet("AppInstInfo", pflag.ExitOnError)
var AppInstInfoNoConfigFlagSet = pflag.NewFlagSet("AppInstInfoNoConfig", pflag.ExitOnError)
var AppInstInfoInState string
var AppInstMetricsIn edgeproto.AppInstMetrics
var AppInstMetricsFlagSet = pflag.NewFlagSet("AppInstMetrics", pflag.ExitOnError)
var AppInstMetricsNoConfigFlagSet = pflag.NewFlagSet("AppInstMetricsNoConfig", pflag.ExitOnError)

func AppInstKeySlicer(in *edgeproto.AppInstKey) []string {
	s := make([]string, 0, 3)
	s = append(s, in.AppKey.DeveloperKey.Name)
	s = append(s, in.AppKey.Name)
	s = append(s, in.AppKey.Version)
	s = append(s, in.CloudletKey.OperatorKey.Name)
	s = append(s, in.CloudletKey.Name)
	s = append(s, strconv.FormatUint(uint64(in.Id), 10))
	return s
}

func AppInstKeyHeaderSlicer() []string {
	s := make([]string, 0, 3)
	s = append(s, "AppKey-DeveloperKey-Name")
	s = append(s, "AppKey-Name")
	s = append(s, "AppKey-Version")
	s = append(s, "CloudletKey-OperatorKey-Name")
	s = append(s, "CloudletKey-Name")
	s = append(s, "Id")
	return s
}

func AppInstKeyWriteOutputArray(objs []*edgeproto.AppInstKey) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstKeyHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(AppInstKeySlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func AppInstKeyWriteOutputOne(obj *edgeproto.AppInstKey) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstKeyHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(AppInstKeySlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func AppPortSlicer(in *edgeproto.AppPort) []string {
	s := make([]string, 0, 3)
	s = append(s, edgeproto.L4Proto_name[int32(in.Proto)])
	s = append(s, strconv.FormatUint(uint64(in.InternalPort), 10))
	s = append(s, strconv.FormatUint(uint64(in.PublicPort), 10))
	return s
}

func AppPortHeaderSlicer() []string {
	s := make([]string, 0, 3)
	s = append(s, "Proto")
	s = append(s, "InternalPort")
	s = append(s, "PublicPort")
	return s
}

func AppPortWriteOutputArray(objs []*edgeproto.AppPort) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppPortHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(AppPortSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func AppPortWriteOutputOne(obj *edgeproto.AppPort) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppPortHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(AppPortSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func AppInstSlicer(in *edgeproto.AppInst) []string {
	s := make([]string, 0, 15)
	if in.Fields == nil {
		in.Fields = make([]string, 1)
	}
	s = append(s, in.Fields[0])
	s = append(s, in.Key.AppKey.DeveloperKey.Name)
	s = append(s, in.Key.AppKey.Name)
	s = append(s, in.Key.AppKey.Version)
	s = append(s, in.Key.CloudletKey.OperatorKey.Name)
	s = append(s, in.Key.CloudletKey.Name)
	s = append(s, strconv.FormatUint(uint64(in.Key.Id), 10))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Lat), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Long), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.HorizontalAccuracy), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.VerticalAccuracy), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Altitude), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Course), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Speed), 'e', -1, 32))
	if in.CloudletLoc.Timestamp == nil {
		in.CloudletLoc.Timestamp = &google_protobuf.Timestamp{}
	}
	_CloudletLoc_TimestampTime := time.Unix(in.CloudletLoc.Timestamp.Seconds, int64(in.CloudletLoc.Timestamp.Nanos))
	s = append(s, _CloudletLoc_TimestampTime.String())
	s = append(s, in.Uri)
	s = append(s, in.ClusterInstKey.ClusterKey.Name)
	s = append(s, in.ClusterInstKey.CloudletKey.OperatorKey.Name)
	s = append(s, in.ClusterInstKey.CloudletKey.Name)
	s = append(s, edgeproto.Liveness_name[int32(in.Liveness)])
	s = append(s, in.ImagePath)
	s = append(s, edgeproto.ImageType_name[int32(in.ImageType)])
	if in.MappedPorts == nil {
		in.MappedPorts = make([]edgeproto.AppPort, 1)
	}
	s = append(s, edgeproto.L4Proto_name[int32(in.MappedPorts[0].Proto)])
	s = append(s, strconv.FormatUint(uint64(in.MappedPorts[0].InternalPort), 10))
	s = append(s, strconv.FormatUint(uint64(in.MappedPorts[0].PublicPort), 10))
	s = append(s, in.MappedPath)
	s = append(s, in.Config)
	s = append(s, in.Flavor.Name)
	s = append(s, edgeproto.AccessLayer_name[int32(in.AccessLayer)])
	s = append(s, edgeproto.TrackedState_name[int32(in.State)])
	if in.Errors == nil {
		in.Errors = make([]string, 1)
	}
	s = append(s, in.Errors[0])
	return s
}

func AppInstHeaderSlicer() []string {
	s := make([]string, 0, 15)
	s = append(s, "Fields")
	s = append(s, "Key-AppKey-DeveloperKey-Name")
	s = append(s, "Key-AppKey-Name")
	s = append(s, "Key-AppKey-Version")
	s = append(s, "Key-CloudletKey-OperatorKey-Name")
	s = append(s, "Key-CloudletKey-Name")
	s = append(s, "Key-Id")
	s = append(s, "CloudletLoc-Lat")
	s = append(s, "CloudletLoc-Long")
	s = append(s, "CloudletLoc-HorizontalAccuracy")
	s = append(s, "CloudletLoc-VerticalAccuracy")
	s = append(s, "CloudletLoc-Altitude")
	s = append(s, "CloudletLoc-Course")
	s = append(s, "CloudletLoc-Speed")
	s = append(s, "CloudletLoc-Timestamp")
	s = append(s, "Uri")
	s = append(s, "ClusterInstKey-ClusterKey-Name")
	s = append(s, "ClusterInstKey-CloudletKey-OperatorKey-Name")
	s = append(s, "ClusterInstKey-CloudletKey-Name")
	s = append(s, "Liveness")
	s = append(s, "ImagePath")
	s = append(s, "ImageType")
	s = append(s, "MappedPorts-Proto")
	s = append(s, "MappedPorts-InternalPort")
	s = append(s, "MappedPorts-PublicPort")
	s = append(s, "MappedPath")
	s = append(s, "Config")
	s = append(s, "Flavor-Name")
	s = append(s, "AccessLayer")
	s = append(s, "State")
	s = append(s, "Errors")
	return s
}

func AppInstWriteOutputArray(objs []*edgeproto.AppInst) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(AppInstSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func AppInstWriteOutputOne(obj *edgeproto.AppInst) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(AppInstSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func AppInstInfoSlicer(in *edgeproto.AppInstInfo) []string {
	s := make([]string, 0, 5)
	if in.Fields == nil {
		in.Fields = make([]string, 1)
	}
	s = append(s, in.Fields[0])
	s = append(s, in.Key.AppKey.DeveloperKey.Name)
	s = append(s, in.Key.AppKey.Name)
	s = append(s, in.Key.AppKey.Version)
	s = append(s, in.Key.CloudletKey.OperatorKey.Name)
	s = append(s, in.Key.CloudletKey.Name)
	s = append(s, strconv.FormatUint(uint64(in.Key.Id), 10))
	s = append(s, strconv.FormatUint(uint64(in.NotifyId), 10))
	s = append(s, edgeproto.TrackedState_name[int32(in.State)])
	if in.Errors == nil {
		in.Errors = make([]string, 1)
	}
	s = append(s, in.Errors[0])
	return s
}

func AppInstInfoHeaderSlicer() []string {
	s := make([]string, 0, 5)
	s = append(s, "Fields")
	s = append(s, "Key-AppKey-DeveloperKey-Name")
	s = append(s, "Key-AppKey-Name")
	s = append(s, "Key-AppKey-Version")
	s = append(s, "Key-CloudletKey-OperatorKey-Name")
	s = append(s, "Key-CloudletKey-Name")
	s = append(s, "Key-Id")
	s = append(s, "NotifyId")
	s = append(s, "State")
	s = append(s, "Errors")
	return s
}

func AppInstInfoWriteOutputArray(objs []*edgeproto.AppInstInfo) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstInfoHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(AppInstInfoSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func AppInstInfoWriteOutputOne(obj *edgeproto.AppInstInfo) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstInfoHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(AppInstInfoSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func AppInstMetricsSlicer(in *edgeproto.AppInstMetrics) []string {
	s := make([]string, 0, 1)
	s = append(s, strconv.FormatUint(uint64(in.Something), 10))
	return s
}

func AppInstMetricsHeaderSlicer() []string {
	s := make([]string, 0, 1)
	s = append(s, "Something")
	return s
}

func AppInstMetricsWriteOutputArray(objs []*edgeproto.AppInstMetrics) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstMetricsHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(AppInstMetricsSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func AppInstMetricsWriteOutputOne(obj *edgeproto.AppInstMetrics) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstMetricsHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(AppInstMetricsSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func AppInstHideTags(in *edgeproto.AppInst) {
	if cmdsup.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cmdsup.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.Uri = ""
	}
	for i0 := 0; i0 < len(in.MappedPorts); i0++ {
	}
	if _, found := tags["nocmp"]; found {
		in.State = 0
	}
	if _, found := tags["nocmp"]; found {
		in.Errors = nil
	}
}

func AppInstInfoHideTags(in *edgeproto.AppInstInfo) {
	if cmdsup.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cmdsup.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.NotifyId = 0
	}
}

var CreateAppInstCmd = &cobra.Command{
	Use: "CreateAppInst",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		if AppInstApiCmd == nil {
			return fmt.Errorf("AppInstApi client not initialized")
		}
		var err error
		err = parseAppInstEnums()
		if err != nil {
			return fmt.Errorf("CreateAppInst failed: %s", err.Error())
		}
		ctx := context.Background()
		stream, err := AppInstApiCmd.CreateAppInst(ctx, &AppInstIn)
		if err != nil {
			return fmt.Errorf("CreateAppInst failed: %s", err.Error())
		}
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("CreateAppInst recv failed: %s", err.Error())
			}
			ResultWriteOutputOne(obj)
		}
		return nil
	},
}

var DeleteAppInstCmd = &cobra.Command{
	Use: "DeleteAppInst",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		if AppInstApiCmd == nil {
			return fmt.Errorf("AppInstApi client not initialized")
		}
		var err error
		err = parseAppInstEnums()
		if err != nil {
			return fmt.Errorf("DeleteAppInst failed: %s", err.Error())
		}
		ctx := context.Background()
		stream, err := AppInstApiCmd.DeleteAppInst(ctx, &AppInstIn)
		if err != nil {
			return fmt.Errorf("DeleteAppInst failed: %s", err.Error())
		}
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("DeleteAppInst recv failed: %s", err.Error())
			}
			ResultWriteOutputOne(obj)
		}
		return nil
	},
}

var UpdateAppInstCmd = &cobra.Command{
	Use: "UpdateAppInst",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		if AppInstApiCmd == nil {
			return fmt.Errorf("AppInstApi client not initialized")
		}
		var err error
		err = parseAppInstEnums()
		if err != nil {
			return fmt.Errorf("UpdateAppInst failed: %s", err.Error())
		}
		AppInstSetFields()
		ctx := context.Background()
		stream, err := AppInstApiCmd.UpdateAppInst(ctx, &AppInstIn)
		if err != nil {
			return fmt.Errorf("UpdateAppInst failed: %s", err.Error())
		}
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("UpdateAppInst recv failed: %s", err.Error())
			}
			ResultWriteOutputOne(obj)
		}
		return nil
	},
}

var ShowAppInstCmd = &cobra.Command{
	Use: "ShowAppInst",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		if AppInstApiCmd == nil {
			return fmt.Errorf("AppInstApi client not initialized")
		}
		var err error
		err = parseAppInstEnums()
		if err != nil {
			return fmt.Errorf("ShowAppInst failed: %s", err.Error())
		}
		ctx := context.Background()
		stream, err := AppInstApiCmd.ShowAppInst(ctx, &AppInstIn)
		if err != nil {
			return fmt.Errorf("ShowAppInst failed: %s", err.Error())
		}
		objs := make([]*edgeproto.AppInst, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("ShowAppInst recv failed: %s", err.Error())
			}
			AppInstHideTags(obj)
			objs = append(objs, obj)
		}
		if len(objs) == 0 {
			return nil
		}
		AppInstWriteOutputArray(objs)
		return nil
	},
}

var AppInstApiCmds = []*cobra.Command{
	CreateAppInstCmd,
	DeleteAppInstCmd,
	UpdateAppInstCmd,
	ShowAppInstCmd,
}

var ShowAppInstInfoCmd = &cobra.Command{
	Use: "ShowAppInstInfo",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		if AppInstInfoApiCmd == nil {
			return fmt.Errorf("AppInstInfoApi client not initialized")
		}
		var err error
		err = parseAppInstInfoEnums()
		if err != nil {
			return fmt.Errorf("ShowAppInstInfo failed: %s", err.Error())
		}
		ctx := context.Background()
		stream, err := AppInstInfoApiCmd.ShowAppInstInfo(ctx, &AppInstInfoIn)
		if err != nil {
			return fmt.Errorf("ShowAppInstInfo failed: %s", err.Error())
		}
		objs := make([]*edgeproto.AppInstInfo, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("ShowAppInstInfo recv failed: %s", err.Error())
			}
			AppInstInfoHideTags(obj)
			objs = append(objs, obj)
		}
		if len(objs) == 0 {
			return nil
		}
		AppInstInfoWriteOutputArray(objs)
		return nil
	},
}

var AppInstInfoApiCmds = []*cobra.Command{
	ShowAppInstInfoCmd,
}

var ShowAppInstMetricsCmd = &cobra.Command{
	Use: "ShowAppInstMetrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		if AppInstMetricsApiCmd == nil {
			return fmt.Errorf("AppInstMetricsApi client not initialized")
		}
		var err error
		ctx := context.Background()
		stream, err := AppInstMetricsApiCmd.ShowAppInstMetrics(ctx, &AppInstMetricsIn)
		if err != nil {
			return fmt.Errorf("ShowAppInstMetrics failed: %s", err.Error())
		}
		objs := make([]*edgeproto.AppInstMetrics, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("ShowAppInstMetrics recv failed: %s", err.Error())
			}
			objs = append(objs, obj)
		}
		if len(objs) == 0 {
			return nil
		}
		AppInstMetricsWriteOutputArray(objs)
		return nil
	},
}

var AppInstMetricsApiCmds = []*cobra.Command{
	ShowAppInstMetricsCmd,
}

func init() {
	AppInstFlagSet.StringVar(&AppInstIn.Key.AppKey.DeveloperKey.Name, "key-appkey-developerkey-name", "", "Key.AppKey.DeveloperKey.Name")
	AppInstFlagSet.StringVar(&AppInstIn.Key.AppKey.Name, "key-appkey-name", "", "Key.AppKey.Name")
	AppInstFlagSet.StringVar(&AppInstIn.Key.AppKey.Version, "key-appkey-version", "", "Key.AppKey.Version")
	AppInstFlagSet.StringVar(&AppInstIn.Key.CloudletKey.OperatorKey.Name, "key-cloudletkey-operatorkey-name", "", "Key.CloudletKey.OperatorKey.Name")
	AppInstFlagSet.StringVar(&AppInstIn.Key.CloudletKey.Name, "key-cloudletkey-name", "", "Key.CloudletKey.Name")
	AppInstFlagSet.Uint64Var(&AppInstIn.Key.Id, "key-id", 0, "Key.Id")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Lat, "cloudletloc-lat", 0, "CloudletLoc.Lat")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Long, "cloudletloc-long", 0, "CloudletLoc.Long")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.HorizontalAccuracy, "cloudletloc-horizontalaccuracy", 0, "CloudletLoc.HorizontalAccuracy")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.VerticalAccuracy, "cloudletloc-verticalaccuracy", 0, "CloudletLoc.VerticalAccuracy")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Altitude, "cloudletloc-altitude", 0, "CloudletLoc.Altitude")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Course, "cloudletloc-course", 0, "CloudletLoc.Course")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Speed, "cloudletloc-speed", 0, "CloudletLoc.Speed")
	AppInstIn.CloudletLoc.Timestamp = &google_protobuf.Timestamp{}
	AppInstNoConfigFlagSet.Int64Var(&AppInstIn.CloudletLoc.Timestamp.Seconds, "cloudletloc-timestamp-seconds", 0, "CloudletLoc.Timestamp.Seconds")
	AppInstNoConfigFlagSet.Int32Var(&AppInstIn.CloudletLoc.Timestamp.Nanos, "cloudletloc-timestamp-nanos", 0, "CloudletLoc.Timestamp.Nanos")
	AppInstNoConfigFlagSet.StringVar(&AppInstIn.Uri, "uri", "", "Uri")
	AppInstNoConfigFlagSet.StringVar(&AppInstIn.ClusterInstKey.ClusterKey.Name, "clusterinstkey-clusterkey-name", "", "ClusterInstKey.ClusterKey.Name")
	AppInstNoConfigFlagSet.StringVar(&AppInstIn.ClusterInstKey.CloudletKey.OperatorKey.Name, "clusterinstkey-cloudletkey-operatorkey-name", "", "ClusterInstKey.CloudletKey.OperatorKey.Name")
	AppInstNoConfigFlagSet.StringVar(&AppInstIn.ClusterInstKey.CloudletKey.Name, "clusterinstkey-cloudletkey-name", "", "ClusterInstKey.CloudletKey.Name")
	AppInstNoConfigFlagSet.StringVar(&AppInstInLiveness, "liveness", "", "one of [LivenessUnknown LivenessStatic LivenessDynamic]")
	AppInstNoConfigFlagSet.StringVar(&AppInstIn.ImagePath, "imagepath", "", "ImagePath")
	AppInstNoConfigFlagSet.StringVar(&AppInstInImageType, "imagetype", "", "one of [ImageTypeUnknown ImageTypeDocker ImageTypeQCOW]")
	AppInstNoConfigFlagSet.StringVar(&AppInstIn.MappedPath, "mappedpath", "", "MappedPath")
	AppInstFlagSet.StringVar(&AppInstIn.Config, "config", "", "Config")
	AppInstFlagSet.StringVar(&AppInstIn.Flavor.Name, "flavor-name", "", "Flavor.Name")
	AppInstFlagSet.StringVar(&AppInstInAccessLayer, "accesslayer", "", "one of [AccessLayerUnknown AccessLayerL4 AccessLayerL7 AccessLayerL4L7]")
	AppInstFlagSet.StringVar(&AppInstInState, "state", "", "one of [TrackedStateUnknown NotPresent CreateRequested Creating CreateError Ready UpdateRequested Updating UpdateError DeleteRequested Deleting DeleteError]")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.DeveloperKey.Name, "key-appkey-developerkey-name", "", "Key.AppKey.DeveloperKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.Name, "key-appkey-name", "", "Key.AppKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.Version, "key-appkey-version", "", "Key.AppKey.Version")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.CloudletKey.OperatorKey.Name, "key-cloudletkey-operatorkey-name", "", "Key.CloudletKey.OperatorKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.CloudletKey.Name, "key-cloudletkey-name", "", "Key.CloudletKey.Name")
	AppInstInfoFlagSet.Uint64Var(&AppInstInfoIn.Key.Id, "key-id", 0, "Key.Id")
	AppInstInfoFlagSet.Int64Var(&AppInstInfoIn.NotifyId, "notifyid", 0, "NotifyId")
	AppInstInfoFlagSet.StringVar(&AppInstInfoInState, "state", "", "one of [TrackedStateUnknown NotPresent CreateRequested Creating CreateError Ready UpdateRequested Updating UpdateError DeleteRequested Deleting DeleteError]")
	AppInstMetricsFlagSet.Uint64Var(&AppInstMetricsIn.Something, "something", 0, "Something")
	CreateAppInstCmd.Flags().AddFlagSet(AppInstFlagSet)
	DeleteAppInstCmd.Flags().AddFlagSet(AppInstFlagSet)
	UpdateAppInstCmd.Flags().AddFlagSet(AppInstFlagSet)
	ShowAppInstCmd.Flags().AddFlagSet(AppInstFlagSet)
	ShowAppInstInfoCmd.Flags().AddFlagSet(AppInstInfoFlagSet)
	ShowAppInstMetricsCmd.Flags().AddFlagSet(AppInstMetricsFlagSet)
}

func AppInstApiAllowNoConfig() {
	CreateAppInstCmd.Flags().AddFlagSet(AppInstNoConfigFlagSet)
	DeleteAppInstCmd.Flags().AddFlagSet(AppInstNoConfigFlagSet)
	UpdateAppInstCmd.Flags().AddFlagSet(AppInstNoConfigFlagSet)
	ShowAppInstCmd.Flags().AddFlagSet(AppInstNoConfigFlagSet)
}

func AppInstInfoApiAllowNoConfig() {
	ShowAppInstInfoCmd.Flags().AddFlagSet(AppInstInfoNoConfigFlagSet)
}

func AppInstMetricsApiAllowNoConfig() {
	ShowAppInstMetricsCmd.Flags().AddFlagSet(AppInstMetricsNoConfigFlagSet)
}

func AppInstSetFields() {
	AppInstIn.Fields = make([]string, 0)
	if AppInstFlagSet.Lookup("key-appkey-developerkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.1.1.2")
	}
	if AppInstFlagSet.Lookup("key-appkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.1.2")
	}
	if AppInstFlagSet.Lookup("key-appkey-version").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.1.3")
	}
	if AppInstFlagSet.Lookup("key-cloudletkey-operatorkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.2.1.1")
	}
	if AppInstFlagSet.Lookup("key-cloudletkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.2.2")
	}
	if AppInstFlagSet.Lookup("key-id").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.3")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-lat").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.1")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-long").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.2")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-horizontalaccuracy").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.3")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-verticalaccuracy").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.4")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-altitude").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.5")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-course").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.6")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-speed").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.7")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-timestamp-seconds").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.8.1")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-timestamp-nanos").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.8.2")
	}
	if AppInstNoConfigFlagSet.Lookup("uri").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "4")
	}
	if AppInstNoConfigFlagSet.Lookup("clusterinstkey-clusterkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "5.1.1")
	}
	if AppInstNoConfigFlagSet.Lookup("clusterinstkey-cloudletkey-operatorkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "5.2.1.1")
	}
	if AppInstNoConfigFlagSet.Lookup("clusterinstkey-cloudletkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "5.2.2")
	}
	if AppInstNoConfigFlagSet.Lookup("liveness").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "6")
	}
	if AppInstNoConfigFlagSet.Lookup("imagepath").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "7")
	}
	if AppInstNoConfigFlagSet.Lookup("imagetype").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "8")
	}
	if AppInstNoConfigFlagSet.Lookup("mappedpath").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "10")
	}
	if AppInstFlagSet.Lookup("config").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "11")
	}
	if AppInstFlagSet.Lookup("flavor-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "12.1")
	}
	if AppInstFlagSet.Lookup("accesslayer").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "13")
	}
	if AppInstFlagSet.Lookup("state").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "14")
	}
}

func AppInstInfoSetFields() {
	AppInstInfoIn.Fields = make([]string, 0)
	if AppInstInfoFlagSet.Lookup("key-appkey-developerkey-name").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.1.1.2")
	}
	if AppInstInfoFlagSet.Lookup("key-appkey-name").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.1.2")
	}
	if AppInstInfoFlagSet.Lookup("key-appkey-version").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.1.3")
	}
	if AppInstInfoFlagSet.Lookup("key-cloudletkey-operatorkey-name").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.2.1.1")
	}
	if AppInstInfoFlagSet.Lookup("key-cloudletkey-name").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.2.2")
	}
	if AppInstInfoFlagSet.Lookup("key-id").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.3")
	}
	if AppInstInfoFlagSet.Lookup("notifyid").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "3")
	}
	if AppInstInfoFlagSet.Lookup("state").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "4")
	}
}

func parseAppInstEnums() error {
	if AppInstInLiveness != "" {
		switch AppInstInLiveness {
		case "LivenessUnknown":
			AppInstIn.Liveness = edgeproto.Liveness(0)
		case "LivenessStatic":
			AppInstIn.Liveness = edgeproto.Liveness(1)
		case "LivenessDynamic":
			AppInstIn.Liveness = edgeproto.Liveness(2)
		default:
			return errors.New("Invalid value for AppInstInLiveness")
		}
	}
	if AppInstInImageType != "" {
		switch AppInstInImageType {
		case "ImageTypeUnknown":
			AppInstIn.ImageType = edgeproto.ImageType(0)
		case "ImageTypeDocker":
			AppInstIn.ImageType = edgeproto.ImageType(1)
		case "ImageTypeQCOW":
			AppInstIn.ImageType = edgeproto.ImageType(2)
		default:
			return errors.New("Invalid value for AppInstInImageType")
		}
	}
	if AppInstInMappedPortsProto != "" {
		switch AppInstInMappedPortsProto {
		case "L4ProtoUnknown":
			AppInstIn.MappedPorts[0].Proto = edgeproto.L4Proto(0)
		case "L4ProtoTCP":
			AppInstIn.MappedPorts[0].Proto = edgeproto.L4Proto(1)
		case "L4ProtoUDP":
			AppInstIn.MappedPorts[0].Proto = edgeproto.L4Proto(2)
		default:
			return errors.New("Invalid value for AppInstInMappedPortsProto")
		}
	}
	if AppInstInAccessLayer != "" {
		switch AppInstInAccessLayer {
		case "AccessLayerUnknown":
			AppInstIn.AccessLayer = edgeproto.AccessLayer(0)
		case "AccessLayerL4":
			AppInstIn.AccessLayer = edgeproto.AccessLayer(1)
		case "AccessLayerL7":
			AppInstIn.AccessLayer = edgeproto.AccessLayer(2)
		case "AccessLayerL4L7":
			AppInstIn.AccessLayer = edgeproto.AccessLayer(3)
		default:
			return errors.New("Invalid value for AppInstInAccessLayer")
		}
	}
	if AppInstInState != "" {
		switch AppInstInState {
		case "TrackedStateUnknown":
			AppInstIn.State = edgeproto.TrackedState(0)
		case "NotPresent":
			AppInstIn.State = edgeproto.TrackedState(1)
		case "CreateRequested":
			AppInstIn.State = edgeproto.TrackedState(2)
		case "Creating":
			AppInstIn.State = edgeproto.TrackedState(3)
		case "CreateError":
			AppInstIn.State = edgeproto.TrackedState(4)
		case "Ready":
			AppInstIn.State = edgeproto.TrackedState(5)
		case "UpdateRequested":
			AppInstIn.State = edgeproto.TrackedState(6)
		case "Updating":
			AppInstIn.State = edgeproto.TrackedState(7)
		case "UpdateError":
			AppInstIn.State = edgeproto.TrackedState(8)
		case "DeleteRequested":
			AppInstIn.State = edgeproto.TrackedState(9)
		case "Deleting":
			AppInstIn.State = edgeproto.TrackedState(10)
		case "DeleteError":
			AppInstIn.State = edgeproto.TrackedState(11)
		default:
			return errors.New("Invalid value for AppInstInState")
		}
	}
	return nil
}

func parseAppInstInfoEnums() error {
	if AppInstInfoInState != "" {
		switch AppInstInfoInState {
		case "TrackedStateUnknown":
			AppInstInfoIn.State = edgeproto.TrackedState(0)
		case "NotPresent":
			AppInstInfoIn.State = edgeproto.TrackedState(1)
		case "CreateRequested":
			AppInstInfoIn.State = edgeproto.TrackedState(2)
		case "Creating":
			AppInstInfoIn.State = edgeproto.TrackedState(3)
		case "CreateError":
			AppInstInfoIn.State = edgeproto.TrackedState(4)
		case "Ready":
			AppInstInfoIn.State = edgeproto.TrackedState(5)
		case "UpdateRequested":
			AppInstInfoIn.State = edgeproto.TrackedState(6)
		case "Updating":
			AppInstInfoIn.State = edgeproto.TrackedState(7)
		case "UpdateError":
			AppInstInfoIn.State = edgeproto.TrackedState(8)
		case "DeleteRequested":
			AppInstInfoIn.State = edgeproto.TrackedState(9)
		case "Deleting":
			AppInstInfoIn.State = edgeproto.TrackedState(10)
		case "DeleteError":
			AppInstInfoIn.State = edgeproto.TrackedState(11)
		default:
			return errors.New("Invalid value for AppInstInfoInState")
		}
	}
	return nil
}
