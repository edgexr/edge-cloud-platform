// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app_inst.proto

package gencmd

import distributed_match_engine "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "strings"
import "strconv"
import "github.com/spf13/cobra"
import "context"
import "os"
import "io"
import "text/tabwriter"
import "github.com/spf13/pflag"
import "errors"
import "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/cmdsup"
import "google.golang.org/grpc/status"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
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
var AppInstInMappedPortsProto string
var AppInstInState string
var AppInstInCrmOverride string
var AppInstInAutoClusterIpAccess string
var AppInstInfoIn edgeproto.AppInstInfo
var AppInstInfoFlagSet = pflag.NewFlagSet("AppInstInfo", pflag.ExitOnError)
var AppInstInfoNoConfigFlagSet = pflag.NewFlagSet("AppInstInfoNoConfig", pflag.ExitOnError)
var AppInstInfoInState string
var AppInstMetricsIn edgeproto.AppInstMetrics
var AppInstMetricsFlagSet = pflag.NewFlagSet("AppInstMetrics", pflag.ExitOnError)
var AppInstMetricsNoConfigFlagSet = pflag.NewFlagSet("AppInstMetricsNoConfig", pflag.ExitOnError)

func AppInstKeySlicer(in *edgeproto.AppInstKey) []string {
	s := make([]string, 0, 2)
	s = append(s, in.AppKey.DeveloperKey.Name)
	s = append(s, in.AppKey.Name)
	s = append(s, in.AppKey.Version)
	s = append(s, in.ClusterInstKey.ClusterKey.Name)
	s = append(s, in.ClusterInstKey.CloudletKey.OperatorKey.Name)
	s = append(s, in.ClusterInstKey.CloudletKey.Name)
	s = append(s, in.ClusterInstKey.Developer)
	return s
}

func AppInstKeyHeaderSlicer() []string {
	s := make([]string, 0, 2)
	s = append(s, "AppKey-DeveloperKey-Name")
	s = append(s, "AppKey-Name")
	s = append(s, "AppKey-Version")
	s = append(s, "ClusterInstKey-ClusterKey-Name")
	s = append(s, "ClusterInstKey-CloudletKey-OperatorKey-Name")
	s = append(s, "ClusterInstKey-CloudletKey-Name")
	s = append(s, "ClusterInstKey-Developer")
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
func AppInstSlicer(in *edgeproto.AppInst) []string {
	s := make([]string, 0, 14)
	if in.Fields == nil {
		in.Fields = make([]string, 1)
	}
	s = append(s, in.Fields[0])
	s = append(s, in.Key.AppKey.DeveloperKey.Name)
	s = append(s, in.Key.AppKey.Name)
	s = append(s, in.Key.AppKey.Version)
	s = append(s, in.Key.ClusterInstKey.ClusterKey.Name)
	s = append(s, in.Key.ClusterInstKey.CloudletKey.OperatorKey.Name)
	s = append(s, in.Key.ClusterInstKey.CloudletKey.Name)
	s = append(s, in.Key.ClusterInstKey.Developer)
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Latitude), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Longitude), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.HorizontalAccuracy), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.VerticalAccuracy), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Altitude), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Course), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.CloudletLoc.Speed), 'e', -1, 32))
	if in.CloudletLoc.Timestamp == nil {
		in.CloudletLoc.Timestamp = &distributed_match_engine.Timestamp{}
	}
	s = append(s, strconv.FormatUint(uint64(in.CloudletLoc.Timestamp.Seconds), 10))
	s = append(s, strconv.FormatUint(uint64(in.CloudletLoc.Timestamp.Nanos), 10))
	s = append(s, in.Uri)
	s = append(s, edgeproto.Liveness_CamelName[int32(in.Liveness)])
	if in.MappedPorts == nil {
		in.MappedPorts = make([]distributed_match_engine.AppPort, 1)
	}
	s = append(s, distributed_match_engine.LProto_CamelName[int32(in.MappedPorts[0].Proto)])
	s = append(s, strconv.FormatUint(uint64(in.MappedPorts[0].InternalPort), 10))
	s = append(s, strconv.FormatUint(uint64(in.MappedPorts[0].PublicPort), 10))
	s = append(s, in.MappedPorts[0].PathPrefix)
	s = append(s, in.MappedPorts[0].FqdnPrefix)
	s = append(s, in.Flavor.Name)
	s = append(s, edgeproto.TrackedState_CamelName[int32(in.State)])
	if in.Errors == nil {
		in.Errors = make([]string, 1)
	}
	s = append(s, in.Errors[0])
	s = append(s, edgeproto.CRMOverride_CamelName[int32(in.CrmOverride)])
	if in.RuntimeInfo.ContainerIds == nil {
		in.RuntimeInfo.ContainerIds = make([]string, 1)
	}
	s = append(s, in.RuntimeInfo.ContainerIds[0])
	s = append(s, in.RuntimeInfo.ConsoleUrl)
	s = append(s, strconv.FormatUint(uint64(in.CreatedAt.Seconds), 10))
	s = append(s, strconv.FormatUint(uint64(in.CreatedAt.Nanos), 10))
	s = append(s, edgeproto.IpAccess_CamelName[int32(in.AutoClusterIpAccess)])
	s = append(s, strconv.FormatUint(uint64(in.Status.TaskNumber), 10))
	s = append(s, strconv.FormatUint(uint64(in.Status.MaxTasks), 10))
	s = append(s, in.Status.TaskName)
	s = append(s, in.Status.StepName)
	return s
}

func AppInstHeaderSlicer() []string {
	s := make([]string, 0, 14)
	s = append(s, "Fields")
	s = append(s, "Key-AppKey-DeveloperKey-Name")
	s = append(s, "Key-AppKey-Name")
	s = append(s, "Key-AppKey-Version")
	s = append(s, "Key-ClusterInstKey-ClusterKey-Name")
	s = append(s, "Key-ClusterInstKey-CloudletKey-OperatorKey-Name")
	s = append(s, "Key-ClusterInstKey-CloudletKey-Name")
	s = append(s, "Key-ClusterInstKey-Developer")
	s = append(s, "CloudletLoc-Latitude")
	s = append(s, "CloudletLoc-Longitude")
	s = append(s, "CloudletLoc-HorizontalAccuracy")
	s = append(s, "CloudletLoc-VerticalAccuracy")
	s = append(s, "CloudletLoc-Altitude")
	s = append(s, "CloudletLoc-Course")
	s = append(s, "CloudletLoc-Speed")
	s = append(s, "CloudletLoc-Timestamp-Seconds")
	s = append(s, "CloudletLoc-Timestamp-Nanos")
	s = append(s, "Uri")
	s = append(s, "Liveness")
	s = append(s, "MappedPorts-Proto")
	s = append(s, "MappedPorts-InternalPort")
	s = append(s, "MappedPorts-PublicPort")
	s = append(s, "MappedPorts-PathPrefix")
	s = append(s, "MappedPorts-FqdnPrefix")
	s = append(s, "Flavor-Name")
	s = append(s, "State")
	s = append(s, "Errors")
	s = append(s, "CrmOverride")
	s = append(s, "RuntimeInfo-ContainerIds")
	s = append(s, "RuntimeInfo-ConsoleUrl")
	s = append(s, "CreatedAt-Seconds")
	s = append(s, "CreatedAt-Nanos")
	s = append(s, "AutoClusterIpAccess")
	s = append(s, "Status-TaskNumber")
	s = append(s, "Status-MaxTasks")
	s = append(s, "Status-TaskName")
	s = append(s, "Status-StepName")
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
func AppInstRuntimeSlicer(in *edgeproto.AppInstRuntime) []string {
	s := make([]string, 0, 2)
	if in.ContainerIds == nil {
		in.ContainerIds = make([]string, 1)
	}
	s = append(s, in.ContainerIds[0])
	s = append(s, in.ConsoleUrl)
	return s
}

func AppInstRuntimeHeaderSlicer() []string {
	s := make([]string, 0, 2)
	s = append(s, "ContainerIds")
	s = append(s, "ConsoleUrl")
	return s
}

func AppInstRuntimeWriteOutputArray(objs []*edgeproto.AppInstRuntime) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstRuntimeHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(AppInstRuntimeSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func AppInstRuntimeWriteOutputOne(obj *edgeproto.AppInstRuntime) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(AppInstRuntimeHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(AppInstRuntimeSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func AppInstInfoSlicer(in *edgeproto.AppInstInfo) []string {
	s := make([]string, 0, 7)
	if in.Fields == nil {
		in.Fields = make([]string, 1)
	}
	s = append(s, in.Fields[0])
	s = append(s, in.Key.AppKey.DeveloperKey.Name)
	s = append(s, in.Key.AppKey.Name)
	s = append(s, in.Key.AppKey.Version)
	s = append(s, in.Key.ClusterInstKey.ClusterKey.Name)
	s = append(s, in.Key.ClusterInstKey.CloudletKey.OperatorKey.Name)
	s = append(s, in.Key.ClusterInstKey.CloudletKey.Name)
	s = append(s, in.Key.ClusterInstKey.Developer)
	s = append(s, strconv.FormatUint(uint64(in.NotifyId), 10))
	s = append(s, edgeproto.TrackedState_CamelName[int32(in.State)])
	if in.Errors == nil {
		in.Errors = make([]string, 1)
	}
	s = append(s, in.Errors[0])
	if in.RuntimeInfo.ContainerIds == nil {
		in.RuntimeInfo.ContainerIds = make([]string, 1)
	}
	s = append(s, in.RuntimeInfo.ContainerIds[0])
	s = append(s, in.RuntimeInfo.ConsoleUrl)
	s = append(s, strconv.FormatUint(uint64(in.Status.TaskNumber), 10))
	s = append(s, strconv.FormatUint(uint64(in.Status.MaxTasks), 10))
	s = append(s, in.Status.TaskName)
	s = append(s, in.Status.StepName)
	return s
}

func AppInstInfoHeaderSlicer() []string {
	s := make([]string, 0, 7)
	s = append(s, "Fields")
	s = append(s, "Key-AppKey-DeveloperKey-Name")
	s = append(s, "Key-AppKey-Name")
	s = append(s, "Key-AppKey-Version")
	s = append(s, "Key-ClusterInstKey-ClusterKey-Name")
	s = append(s, "Key-ClusterInstKey-CloudletKey-OperatorKey-Name")
	s = append(s, "Key-ClusterInstKey-CloudletKey-Name")
	s = append(s, "Key-ClusterInstKey-Developer")
	s = append(s, "NotifyId")
	s = append(s, "State")
	s = append(s, "Errors")
	s = append(s, "RuntimeInfo-ContainerIds")
	s = append(s, "RuntimeInfo-ConsoleUrl")
	s = append(s, "Status-TaskNumber")
	s = append(s, "Status-MaxTasks")
	s = append(s, "Status-TaskName")
	s = append(s, "Status-StepName")
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
		in.MappedPorts = nil
	}
	if _, found := tags["nocmp"]; found {
		in.State = 0
	}
	if _, found := tags["nocmp"]; found {
		in.Errors = nil
	}
	if _, found := tags["nocmp"]; found {
		in.CrmOverride = 0
	}
	if _, found := tags["nocmp"]; found {
		in.RuntimeInfo.ContainerIds = nil
	}
	if _, found := tags["nocmp"]; found {
		in.RuntimeInfo.ConsoleUrl = ""
	}
	if _, found := tags["timestamp"]; found {
		in.CreatedAt = distributed_match_engine.Timestamp{}
	}
}

func AppInstRuntimeHideTags(in *edgeproto.AppInstRuntime) {
	if cmdsup.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cmdsup.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.ContainerIds = nil
	}
	if _, found := tags["nocmp"]; found {
		in.ConsoleUrl = ""
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
	if _, found := tags["nocmp"]; found {
		in.RuntimeInfo.ContainerIds = nil
	}
	if _, found := tags["nocmp"]; found {
		in.RuntimeInfo.ConsoleUrl = ""
	}
}

var CreateAppInstCmd = &cobra.Command{
	Use: "CreateAppInst",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		err := parseAppInstEnums()
		if err != nil {
			return fmt.Errorf("CreateAppInst failed: %s", err.Error())
		}
		return CreateAppInst(&AppInstIn)
	},
}

func CreateAppInst(in *edgeproto.AppInst) error {
	if AppInstApiCmd == nil {
		return fmt.Errorf("AppInstApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AppInstApiCmd.CreateAppInst(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("CreateAppInst failed: %s", errstr)
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
}

func CreateAppInsts(data []edgeproto.AppInst, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("CreateAppInst %v\n", data[ii])
		myerr := CreateAppInst(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteAppInstCmd = &cobra.Command{
	Use: "DeleteAppInst",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		err := parseAppInstEnums()
		if err != nil {
			return fmt.Errorf("DeleteAppInst failed: %s", err.Error())
		}
		return DeleteAppInst(&AppInstIn)
	},
}

func DeleteAppInst(in *edgeproto.AppInst) error {
	if AppInstApiCmd == nil {
		return fmt.Errorf("AppInstApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AppInstApiCmd.DeleteAppInst(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteAppInst failed: %s", errstr)
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
}

func DeleteAppInsts(data []edgeproto.AppInst, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DeleteAppInst %v\n", data[ii])
		myerr := DeleteAppInst(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var UpdateAppInstCmd = &cobra.Command{
	Use: "UpdateAppInst",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		err := parseAppInstEnums()
		if err != nil {
			return fmt.Errorf("UpdateAppInst failed: %s", err.Error())
		}
		AppInstSetFields()
		return UpdateAppInst(&AppInstIn)
	},
}

func UpdateAppInst(in *edgeproto.AppInst) error {
	if AppInstApiCmd == nil {
		return fmt.Errorf("AppInstApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AppInstApiCmd.UpdateAppInst(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("UpdateAppInst failed: %s", errstr)
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
}

func UpdateAppInsts(data []edgeproto.AppInst, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("UpdateAppInst %v\n", data[ii])
		myerr := UpdateAppInst(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowAppInstCmd = &cobra.Command{
	Use: "ShowAppInst",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		err := parseAppInstEnums()
		if err != nil {
			return fmt.Errorf("ShowAppInst failed: %s", err.Error())
		}
		return ShowAppInst(&AppInstIn)
	},
}

func ShowAppInst(in *edgeproto.AppInst) error {
	if AppInstApiCmd == nil {
		return fmt.Errorf("AppInstApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AppInstApiCmd.ShowAppInst(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowAppInst failed: %s", errstr)
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
}

func ShowAppInsts(data []edgeproto.AppInst, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowAppInst %v\n", data[ii])
		myerr := ShowAppInst(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
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
		err := parseAppInstInfoEnums()
		if err != nil {
			return fmt.Errorf("ShowAppInstInfo failed: %s", err.Error())
		}
		return ShowAppInstInfo(&AppInstInfoIn)
	},
}

func ShowAppInstInfo(in *edgeproto.AppInstInfo) error {
	if AppInstInfoApiCmd == nil {
		return fmt.Errorf("AppInstInfoApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AppInstInfoApiCmd.ShowAppInstInfo(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowAppInstInfo failed: %s", errstr)
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
}

func ShowAppInstInfos(data []edgeproto.AppInstInfo, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowAppInstInfo %v\n", data[ii])
		myerr := ShowAppInstInfo(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AppInstInfoApiCmds = []*cobra.Command{
	ShowAppInstInfoCmd,
}

var ShowAppInstMetricsCmd = &cobra.Command{
	Use: "ShowAppInstMetrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		return ShowAppInstMetrics(&AppInstMetricsIn)
	},
}

func ShowAppInstMetrics(in *edgeproto.AppInstMetrics) error {
	if AppInstMetricsApiCmd == nil {
		return fmt.Errorf("AppInstMetricsApi client not initialized")
	}
	ctx := context.Background()
	stream, err := AppInstMetricsApiCmd.ShowAppInstMetrics(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowAppInstMetrics failed: %s", errstr)
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
}

func ShowAppInstMetricss(data []edgeproto.AppInstMetrics, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowAppInstMetrics %v\n", data[ii])
		myerr := ShowAppInstMetrics(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var AppInstMetricsApiCmds = []*cobra.Command{
	ShowAppInstMetricsCmd,
}

func init() {
	AppInstFlagSet.StringVar(&AppInstIn.Key.AppKey.DeveloperKey.Name, "key-appkey-developerkey-name", "", "Key.AppKey.DeveloperKey.Name")
	AppInstFlagSet.StringVar(&AppInstIn.Key.AppKey.Name, "key-appkey-name", "", "Key.AppKey.Name")
	AppInstFlagSet.StringVar(&AppInstIn.Key.AppKey.Version, "key-appkey-version", "", "Key.AppKey.Version")
	AppInstFlagSet.StringVar(&AppInstIn.Key.ClusterInstKey.ClusterKey.Name, "key-clusterinstkey-clusterkey-name", "", "Key.ClusterInstKey.ClusterKey.Name")
	AppInstFlagSet.StringVar(&AppInstIn.Key.ClusterInstKey.CloudletKey.OperatorKey.Name, "key-clusterinstkey-cloudletkey-operatorkey-name", "", "Key.ClusterInstKey.CloudletKey.OperatorKey.Name")
	AppInstFlagSet.StringVar(&AppInstIn.Key.ClusterInstKey.CloudletKey.Name, "key-clusterinstkey-cloudletkey-name", "", "Key.ClusterInstKey.CloudletKey.Name")
	AppInstFlagSet.StringVar(&AppInstIn.Key.ClusterInstKey.Developer, "key-clusterinstkey-developer", "", "Key.ClusterInstKey.Developer")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Latitude, "cloudletloc-latitude", 0, "CloudletLoc.Latitude")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Longitude, "cloudletloc-longitude", 0, "CloudletLoc.Longitude")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.HorizontalAccuracy, "cloudletloc-horizontalaccuracy", 0, "CloudletLoc.HorizontalAccuracy")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.VerticalAccuracy, "cloudletloc-verticalaccuracy", 0, "CloudletLoc.VerticalAccuracy")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Altitude, "cloudletloc-altitude", 0, "CloudletLoc.Altitude")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Course, "cloudletloc-course", 0, "CloudletLoc.Course")
	AppInstNoConfigFlagSet.Float64Var(&AppInstIn.CloudletLoc.Speed, "cloudletloc-speed", 0, "CloudletLoc.Speed")
	AppInstIn.CloudletLoc.Timestamp = &distributed_match_engine.Timestamp{}
	AppInstNoConfigFlagSet.Int64Var(&AppInstIn.CloudletLoc.Timestamp.Seconds, "cloudletloc-timestamp-seconds", 0, "CloudletLoc.Timestamp.Seconds")
	AppInstNoConfigFlagSet.Int32Var(&AppInstIn.CloudletLoc.Timestamp.Nanos, "cloudletloc-timestamp-nanos", 0, "CloudletLoc.Timestamp.Nanos")
	AppInstFlagSet.StringVar(&AppInstIn.Uri, "uri", "", "Uri")
	AppInstNoConfigFlagSet.StringVar(&AppInstInLiveness, "liveness", "", "one of [LivenessUnknown LivenessStatic LivenessDynamic]")
	AppInstFlagSet.StringVar(&AppInstIn.Flavor.Name, "flavor-name", "", "Flavor.Name")
	AppInstFlagSet.StringVar(&AppInstInState, "state", "", "one of [TrackedStateUnknown NotPresent CreateRequested Creating CreateError Ready UpdateRequested Updating UpdateError DeleteRequested Deleting DeleteError DeletePrepare]")
	AppInstFlagSet.StringVar(&AppInstInCrmOverride, "crmoverride", "", "one of [NoOverride IgnoreCrmErrors IgnoreCrm IgnoreTransientState IgnoreCrmAndTransientState]")
	AppInstFlagSet.StringVar(&AppInstIn.RuntimeInfo.ConsoleUrl, "runtimeinfo-consoleurl", "", "RuntimeInfo.ConsoleUrl")
	AppInstNoConfigFlagSet.Int64Var(&AppInstIn.CreatedAt.Seconds, "createdat-seconds", 0, "CreatedAt.Seconds")
	AppInstNoConfigFlagSet.Int32Var(&AppInstIn.CreatedAt.Nanos, "createdat-nanos", 0, "CreatedAt.Nanos")
	AppInstFlagSet.StringVar(&AppInstInAutoClusterIpAccess, "autoclusteripaccess", "", "one of [IpAccessUnknown IpAccessDedicated IpAccessDedicatedOrShared IpAccessShared]")
	AppInstNoConfigFlagSet.Uint32Var(&AppInstIn.Status.TaskNumber, "status-tasknumber", 0, "Status.TaskNumber")
	AppInstNoConfigFlagSet.Uint32Var(&AppInstIn.Status.MaxTasks, "status-maxtasks", 0, "Status.MaxTasks")
	AppInstNoConfigFlagSet.StringVar(&AppInstIn.Status.TaskName, "status-taskname", "", "Status.TaskName")
	AppInstNoConfigFlagSet.StringVar(&AppInstIn.Status.StepName, "status-stepname", "", "Status.StepName")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.DeveloperKey.Name, "key-appkey-developerkey-name", "", "Key.AppKey.DeveloperKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.Name, "key-appkey-name", "", "Key.AppKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.Version, "key-appkey-version", "", "Key.AppKey.Version")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.ClusterInstKey.ClusterKey.Name, "key-clusterinstkey-clusterkey-name", "", "Key.ClusterInstKey.ClusterKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.ClusterInstKey.CloudletKey.OperatorKey.Name, "key-clusterinstkey-cloudletkey-operatorkey-name", "", "Key.ClusterInstKey.CloudletKey.OperatorKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.ClusterInstKey.CloudletKey.Name, "key-clusterinstkey-cloudletkey-name", "", "Key.ClusterInstKey.CloudletKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.ClusterInstKey.Developer, "key-clusterinstkey-developer", "", "Key.ClusterInstKey.Developer")
	AppInstInfoFlagSet.Int64Var(&AppInstInfoIn.NotifyId, "notifyid", 0, "NotifyId")
	AppInstInfoFlagSet.StringVar(&AppInstInfoInState, "state", "", "one of [TrackedStateUnknown NotPresent CreateRequested Creating CreateError Ready UpdateRequested Updating UpdateError DeleteRequested Deleting DeleteError DeletePrepare]")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.RuntimeInfo.ConsoleUrl, "runtimeinfo-consoleurl", "", "RuntimeInfo.ConsoleUrl")
	AppInstInfoFlagSet.Uint32Var(&AppInstInfoIn.Status.TaskNumber, "status-tasknumber", 0, "Status.TaskNumber")
	AppInstInfoFlagSet.Uint32Var(&AppInstInfoIn.Status.MaxTasks, "status-maxtasks", 0, "Status.MaxTasks")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Status.TaskName, "status-taskname", "", "Status.TaskName")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Status.StepName, "status-stepname", "", "Status.StepName")
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
	if AppInstFlagSet.Lookup("key-clusterinstkey-clusterkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.4.1.1")
	}
	if AppInstFlagSet.Lookup("key-clusterinstkey-cloudletkey-operatorkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.4.2.1.1")
	}
	if AppInstFlagSet.Lookup("key-clusterinstkey-cloudletkey-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.4.2.2")
	}
	if AppInstFlagSet.Lookup("key-clusterinstkey-developer").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "2.4.3")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-latitude").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.1")
	}
	if AppInstNoConfigFlagSet.Lookup("cloudletloc-longitude").Changed {
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
	if AppInstFlagSet.Lookup("uri").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "4")
	}
	if AppInstNoConfigFlagSet.Lookup("liveness").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "6")
	}
	if AppInstFlagSet.Lookup("flavor-name").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "12.1")
	}
	if AppInstFlagSet.Lookup("state").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "14")
	}
	if AppInstFlagSet.Lookup("crmoverride").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "16")
	}
	if AppInstFlagSet.Lookup("runtimeinfo-consoleurl").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "17.2")
	}
	if AppInstNoConfigFlagSet.Lookup("createdat-seconds").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "21.1")
	}
	if AppInstNoConfigFlagSet.Lookup("createdat-nanos").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "21.2")
	}
	if AppInstFlagSet.Lookup("autoclusteripaccess").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "22")
	}
	if AppInstNoConfigFlagSet.Lookup("status-tasknumber").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "23.1")
	}
	if AppInstNoConfigFlagSet.Lookup("status-maxtasks").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "23.2")
	}
	if AppInstNoConfigFlagSet.Lookup("status-taskname").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "23.3")
	}
	if AppInstNoConfigFlagSet.Lookup("status-stepname").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "23.4")
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
	if AppInstInfoFlagSet.Lookup("key-clusterinstkey-clusterkey-name").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.4.1.1")
	}
	if AppInstInfoFlagSet.Lookup("key-clusterinstkey-cloudletkey-operatorkey-name").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.4.2.1.1")
	}
	if AppInstInfoFlagSet.Lookup("key-clusterinstkey-cloudletkey-name").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.4.2.2")
	}
	if AppInstInfoFlagSet.Lookup("key-clusterinstkey-developer").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "2.4.3")
	}
	if AppInstInfoFlagSet.Lookup("notifyid").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "3")
	}
	if AppInstInfoFlagSet.Lookup("state").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "4")
	}
	if AppInstInfoFlagSet.Lookup("runtimeinfo-consoleurl").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "6.2")
	}
	if AppInstInfoNoConfigFlagSet.Lookup("status-tasknumber").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "7.1")
	}
	if AppInstInfoNoConfigFlagSet.Lookup("status-maxtasks").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "7.2")
	}
	if AppInstInfoNoConfigFlagSet.Lookup("status-taskname").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "7.3")
	}
	if AppInstInfoNoConfigFlagSet.Lookup("status-stepname").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "7.4")
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
	if AppInstInMappedPortsProto != "" {
		switch AppInstInMappedPortsProto {
		case "LProtoUnknown":
			AppInstIn.MappedPorts[0].Proto = distributed_match_engine.LProto(0)
		case "LProtoTcp":
			AppInstIn.MappedPorts[0].Proto = distributed_match_engine.LProto(1)
		case "LProtoUdp":
			AppInstIn.MappedPorts[0].Proto = distributed_match_engine.LProto(2)
		case "LProtoHttp":
			AppInstIn.MappedPorts[0].Proto = distributed_match_engine.LProto(3)
		default:
			return errors.New("Invalid value for AppInstInMappedPortsProto")
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
		case "DeletePrepare":
			AppInstIn.State = edgeproto.TrackedState(12)
		default:
			return errors.New("Invalid value for AppInstInState")
		}
	}
	if AppInstInCrmOverride != "" {
		switch AppInstInCrmOverride {
		case "NoOverride":
			AppInstIn.CrmOverride = edgeproto.CRMOverride(0)
		case "IgnoreCrmErrors":
			AppInstIn.CrmOverride = edgeproto.CRMOverride(1)
		case "IgnoreCrm":
			AppInstIn.CrmOverride = edgeproto.CRMOverride(2)
		case "IgnoreTransientState":
			AppInstIn.CrmOverride = edgeproto.CRMOverride(3)
		case "IgnoreCrmAndTransientState":
			AppInstIn.CrmOverride = edgeproto.CRMOverride(4)
		default:
			return errors.New("Invalid value for AppInstInCrmOverride")
		}
	}
	if AppInstInAutoClusterIpAccess != "" {
		switch AppInstInAutoClusterIpAccess {
		case "IpAccessUnknown":
			AppInstIn.AutoClusterIpAccess = edgeproto.IpAccess(0)
		case "IpAccessDedicated":
			AppInstIn.AutoClusterIpAccess = edgeproto.IpAccess(1)
		case "IpAccessDedicatedOrShared":
			AppInstIn.AutoClusterIpAccess = edgeproto.IpAccess(2)
		case "IpAccessShared":
			AppInstIn.AutoClusterIpAccess = edgeproto.IpAccess(3)
		default:
			return errors.New("Invalid value for AppInstInAutoClusterIpAccess")
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
		case "DeletePrepare":
			AppInstInfoIn.State = edgeproto.TrackedState(12)
		default:
			return errors.New("Invalid value for AppInstInfoInState")
		}
	}
	return nil
}
