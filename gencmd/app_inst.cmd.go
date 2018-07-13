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
import "encoding/json"
import "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/cmdsup"
import "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/yaml"
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
var AppInstMetricsIn edgeproto.AppInstMetrics
var AppInstMetricsFlagSet = pflag.NewFlagSet("AppInstMetrics", pflag.ExitOnError)
var AppInstIn edgeproto.AppInst
var AppInstFlagSet = pflag.NewFlagSet("AppInst", pflag.ExitOnError)
var AppInstInLiveness string
var AppInstInfoIn edgeproto.AppInstInfo
var AppInstInfoFlagSet = pflag.NewFlagSet("AppInstInfo", pflag.ExitOnError)
var LivenessStrings = []string{
	"UNKNOWN",
	"STATIC",
	"DYNAMIC",
}

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

func AppInstSlicer(in *edgeproto.AppInst) []string {
	s := make([]string, 0, 7)
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
	s = append(s, "")
	for i, b := range in.Ip {
		s[len(s)-1] += fmt.Sprintf("%v", b)
		if i < 3 {
			s[len(s)-1] += "."
		}
	}
	s = append(s, edgeproto.AppInst_Liveness_name[int32(in.Liveness)])
	s = append(s, in.AppPath)
	return s
}

func AppInstHeaderSlicer() []string {
	s := make([]string, 0, 7)
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
	s = append(s, "Ip")
	s = append(s, "Liveness")
	s = append(s, "AppPath")
	return s
}

func AppInstInfoSlicer(in *edgeproto.AppInstInfo) []string {
	s := make([]string, 0, 8)
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
	s = append(s, strconv.FormatUint(uint64(in.Load), 10))
	s = append(s, strconv.FormatUint(uint64(in.Cpu), 10))
	s = append(s, strconv.FormatUint(uint64(in.MaxDisk), 10))
	s = append(s, strconv.FormatUint(uint64(in.NetworkIn), 10))
	s = append(s, strconv.FormatUint(uint64(in.NetworkOut), 10))
	return s
}

func AppInstInfoHeaderSlicer() []string {
	s := make([]string, 0, 8)
	s = append(s, "Fields")
	s = append(s, "Key-AppKey-DeveloperKey-Name")
	s = append(s, "Key-AppKey-Name")
	s = append(s, "Key-AppKey-Version")
	s = append(s, "Key-CloudletKey-OperatorKey-Name")
	s = append(s, "Key-CloudletKey-Name")
	s = append(s, "Key-Id")
	s = append(s, "NotifyId")
	s = append(s, "Load")
	s = append(s, "Cpu")
	s = append(s, "MaxDisk")
	s = append(s, "NetworkIn")
	s = append(s, "NetworkOut")
	return s
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

var CreateAppInstCmd = &cobra.Command{
	Use: "CreateAppInst",
	Run: func(cmd *cobra.Command, args []string) {
		if AppInstApiCmd == nil {
			fmt.Println("AppInstApi client not initialized")
			return
		}
		var err error
		err = parseAppInstEnums()
		if err != nil {
			fmt.Println("CreateAppInst: ", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		objs, err := AppInstApiCmd.CreateAppInst(ctx, &AppInstIn)
		cancel()
		if err != nil {
			fmt.Println("CreateAppInst failed: ", err)
			return
		}
		switch cmdsup.OutputFormat {
		case cmdsup.OutputFormatYaml:
			output, err := yaml.Marshal(objs)
			if err != nil {
				fmt.Printf("Yaml failed to marshal: %s\n", err)
				return
			}
			fmt.Print(string(output))
		case cmdsup.OutputFormatJson:
			output, err := json.MarshalIndent(objs, "", "  ")
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatJsonCompact:
			output, err := json.Marshal(objs)
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatTable:
			output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			fmt.Fprintln(output, strings.Join(ResultHeaderSlicer(), "\t"))
			fmt.Fprintln(output, strings.Join(ResultSlicer(objs), "\t"))
			output.Flush()
		}
	},
}

var DeleteAppInstCmd = &cobra.Command{
	Use: "DeleteAppInst",
	Run: func(cmd *cobra.Command, args []string) {
		if AppInstApiCmd == nil {
			fmt.Println("AppInstApi client not initialized")
			return
		}
		var err error
		err = parseAppInstEnums()
		if err != nil {
			fmt.Println("DeleteAppInst: ", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		objs, err := AppInstApiCmd.DeleteAppInst(ctx, &AppInstIn)
		cancel()
		if err != nil {
			fmt.Println("DeleteAppInst failed: ", err)
			return
		}
		switch cmdsup.OutputFormat {
		case cmdsup.OutputFormatYaml:
			output, err := yaml.Marshal(objs)
			if err != nil {
				fmt.Printf("Yaml failed to marshal: %s\n", err)
				return
			}
			fmt.Print(string(output))
		case cmdsup.OutputFormatJson:
			output, err := json.MarshalIndent(objs, "", "  ")
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatJsonCompact:
			output, err := json.Marshal(objs)
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatTable:
			output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			fmt.Fprintln(output, strings.Join(ResultHeaderSlicer(), "\t"))
			fmt.Fprintln(output, strings.Join(ResultSlicer(objs), "\t"))
			output.Flush()
		}
	},
}

var UpdateAppInstCmd = &cobra.Command{
	Use: "UpdateAppInst",
	Run: func(cmd *cobra.Command, args []string) {
		if AppInstApiCmd == nil {
			fmt.Println("AppInstApi client not initialized")
			return
		}
		var err error
		err = parseAppInstEnums()
		if err != nil {
			fmt.Println("UpdateAppInst: ", err)
			return
		}
		AppInstSetFields()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		objs, err := AppInstApiCmd.UpdateAppInst(ctx, &AppInstIn)
		cancel()
		if err != nil {
			fmt.Println("UpdateAppInst failed: ", err)
			return
		}
		switch cmdsup.OutputFormat {
		case cmdsup.OutputFormatYaml:
			output, err := yaml.Marshal(objs)
			if err != nil {
				fmt.Printf("Yaml failed to marshal: %s\n", err)
				return
			}
			fmt.Print(string(output))
		case cmdsup.OutputFormatJson:
			output, err := json.MarshalIndent(objs, "", "  ")
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatJsonCompact:
			output, err := json.Marshal(objs)
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatTable:
			output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			fmt.Fprintln(output, strings.Join(ResultHeaderSlicer(), "\t"))
			fmt.Fprintln(output, strings.Join(ResultSlicer(objs), "\t"))
			output.Flush()
		}
	},
}

var ShowAppInstCmd = &cobra.Command{
	Use: "ShowAppInst",
	Run: func(cmd *cobra.Command, args []string) {
		if AppInstApiCmd == nil {
			fmt.Println("AppInstApi client not initialized")
			return
		}
		var err error
		err = parseAppInstEnums()
		if err != nil {
			fmt.Println("ShowAppInst: ", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stream, err := AppInstApiCmd.ShowAppInst(ctx, &AppInstIn)
		if err != nil {
			fmt.Println("ShowAppInst failed: ", err)
			return
		}
		objs := make([]*edgeproto.AppInst, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println("ShowAppInst recv failed: ", err)
				break
			}
			objs = append(objs, obj)
		}
		if len(objs) == 0 {
			return
		}
		switch cmdsup.OutputFormat {
		case cmdsup.OutputFormatYaml:
			output, err := yaml.Marshal(objs)
			if err != nil {
				fmt.Printf("Yaml failed to marshal: %s\n", err)
				return
			}
			fmt.Print(string(output))
		case cmdsup.OutputFormatJson:
			output, err := json.MarshalIndent(objs, "", "  ")
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatJsonCompact:
			output, err := json.Marshal(objs)
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatTable:
			output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			fmt.Fprintln(output, strings.Join(AppInstHeaderSlicer(), "\t"))
			for _, obj := range objs {
				fmt.Fprintln(output, strings.Join(AppInstSlicer(obj), "\t"))
			}
			output.Flush()
		}
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
	Run: func(cmd *cobra.Command, args []string) {
		if AppInstInfoApiCmd == nil {
			fmt.Println("AppInstInfoApi client not initialized")
			return
		}
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stream, err := AppInstInfoApiCmd.ShowAppInstInfo(ctx, &AppInstInfoIn)
		if err != nil {
			fmt.Println("ShowAppInstInfo failed: ", err)
			return
		}
		objs := make([]*edgeproto.AppInstInfo, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println("ShowAppInstInfo recv failed: ", err)
				break
			}
			objs = append(objs, obj)
		}
		if len(objs) == 0 {
			return
		}
		switch cmdsup.OutputFormat {
		case cmdsup.OutputFormatYaml:
			output, err := yaml.Marshal(objs)
			if err != nil {
				fmt.Printf("Yaml failed to marshal: %s\n", err)
				return
			}
			fmt.Print(string(output))
		case cmdsup.OutputFormatJson:
			output, err := json.MarshalIndent(objs, "", "  ")
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatJsonCompact:
			output, err := json.Marshal(objs)
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatTable:
			output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			fmt.Fprintln(output, strings.Join(AppInstInfoHeaderSlicer(), "\t"))
			for _, obj := range objs {
				fmt.Fprintln(output, strings.Join(AppInstInfoSlicer(obj), "\t"))
			}
			output.Flush()
		}
	},
}

var AppInstInfoApiCmds = []*cobra.Command{
	ShowAppInstInfoCmd,
}

var ShowAppInstMetricsCmd = &cobra.Command{
	Use: "ShowAppInstMetrics",
	Run: func(cmd *cobra.Command, args []string) {
		if AppInstMetricsApiCmd == nil {
			fmt.Println("AppInstMetricsApi client not initialized")
			return
		}
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stream, err := AppInstMetricsApiCmd.ShowAppInstMetrics(ctx, &AppInstMetricsIn)
		if err != nil {
			fmt.Println("ShowAppInstMetrics failed: ", err)
			return
		}
		objs := make([]*edgeproto.AppInstMetrics, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println("ShowAppInstMetrics recv failed: ", err)
				break
			}
			objs = append(objs, obj)
		}
		if len(objs) == 0 {
			return
		}
		switch cmdsup.OutputFormat {
		case cmdsup.OutputFormatYaml:
			output, err := yaml.Marshal(objs)
			if err != nil {
				fmt.Printf("Yaml failed to marshal: %s\n", err)
				return
			}
			fmt.Print(string(output))
		case cmdsup.OutputFormatJson:
			output, err := json.MarshalIndent(objs, "", "  ")
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatJsonCompact:
			output, err := json.Marshal(objs)
			if err != nil {
				fmt.Printf("Json failed to marshal: %s\n", err)
				return
			}
			fmt.Println(string(output))
		case cmdsup.OutputFormatTable:
			output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			fmt.Fprintln(output, strings.Join(AppInstMetricsHeaderSlicer(), "\t"))
			for _, obj := range objs {
				fmt.Fprintln(output, strings.Join(AppInstMetricsSlicer(obj), "\t"))
			}
			output.Flush()
		}
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
	AppInstFlagSet.StringVar(&AppInstIn.Uri, "uri", "", "Uri")
	AppInstFlagSet.BytesHexVar(&AppInstIn.Ip, "ip", nil, "Ip")
	AppInstFlagSet.StringVar(&AppInstInLiveness, "liveness", "", "one of [UNKNOWN STATIC DYNAMIC]")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.DeveloperKey.Name, "key-appkey-developerkey-name", "", "Key.AppKey.DeveloperKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.Name, "key-appkey-name", "", "Key.AppKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.AppKey.Version, "key-appkey-version", "", "Key.AppKey.Version")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.CloudletKey.OperatorKey.Name, "key-cloudletkey-operatorkey-name", "", "Key.CloudletKey.OperatorKey.Name")
	AppInstInfoFlagSet.StringVar(&AppInstInfoIn.Key.CloudletKey.Name, "key-cloudletkey-name", "", "Key.CloudletKey.Name")
	AppInstInfoFlagSet.Uint64Var(&AppInstInfoIn.Key.Id, "key-id", 0, "Key.Id")
	AppInstInfoFlagSet.Int64Var(&AppInstInfoIn.NotifyId, "notifyid", 0, "NotifyId")
	AppInstInfoFlagSet.Uint64Var(&AppInstInfoIn.Load, "load", 0, "Load")
	AppInstInfoFlagSet.Uint64Var(&AppInstInfoIn.Cpu, "cpu", 0, "Cpu")
	AppInstInfoFlagSet.Uint64Var(&AppInstInfoIn.MaxDisk, "maxdisk", 0, "MaxDisk")
	AppInstInfoFlagSet.Uint64Var(&AppInstInfoIn.NetworkIn, "networkin", 0, "NetworkIn")
	AppInstInfoFlagSet.Uint64Var(&AppInstInfoIn.NetworkOut, "networkout", 0, "NetworkOut")
	AppInstMetricsFlagSet.Uint64Var(&AppInstMetricsIn.Something, "something", 0, "Something")
	CreateAppInstCmd.Flags().AddFlagSet(AppInstFlagSet)
	DeleteAppInstCmd.Flags().AddFlagSet(AppInstFlagSet)
	UpdateAppInstCmd.Flags().AddFlagSet(AppInstFlagSet)
	ShowAppInstCmd.Flags().AddFlagSet(AppInstFlagSet)
	ShowAppInstInfoCmd.Flags().AddFlagSet(AppInstInfoFlagSet)
	ShowAppInstMetricsCmd.Flags().AddFlagSet(AppInstMetricsFlagSet)
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
	if AppInstFlagSet.Lookup("cloudletloc-lat").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.1")
	}
	if AppInstFlagSet.Lookup("cloudletloc-long").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.2")
	}
	if AppInstFlagSet.Lookup("cloudletloc-horizontalaccuracy").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.3")
	}
	if AppInstFlagSet.Lookup("cloudletloc-verticalaccuracy").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.4")
	}
	if AppInstFlagSet.Lookup("cloudletloc-altitude").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.5")
	}
	if AppInstFlagSet.Lookup("cloudletloc-course").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.6")
	}
	if AppInstFlagSet.Lookup("cloudletloc-speed").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.7")
	}
	if AppInstFlagSet.Lookup("cloudletloc-timestamp-seconds").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.8.1")
	}
	if AppInstFlagSet.Lookup("cloudletloc-timestamp-nanos").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "3.8.2")
	}
	if AppInstFlagSet.Lookup("uri").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "4")
	}
	if AppInstFlagSet.Lookup("ip").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "8")
	}
	if AppInstFlagSet.Lookup("liveness").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "6")
	}
	if AppInstFlagSet.Lookup("apppath").Changed {
		AppInstIn.Fields = append(AppInstIn.Fields, "7")
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
	if AppInstInfoFlagSet.Lookup("load").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "4")
	}
	if AppInstInfoFlagSet.Lookup("cpu").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "5")
	}
	if AppInstInfoFlagSet.Lookup("maxdisk").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "6")
	}
	if AppInstInfoFlagSet.Lookup("networkin").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "7")
	}
	if AppInstInfoFlagSet.Lookup("networkout").Changed {
		AppInstInfoIn.Fields = append(AppInstInfoIn.Fields, "8")
	}
}
func parseAppInstEnums() error {
	if AppInstInLiveness != "" {
		switch AppInstInLiveness {
		case "UNKNOWN":
			AppInstIn.Liveness = edgeproto.AppInst_Liveness(0)
		case "STATIC":
			AppInstIn.Liveness = edgeproto.AppInst_Liveness(1)
		case "DYNAMIC":
			AppInstIn.Liveness = edgeproto.AppInst_Liveness(2)
		default:
			return errors.New("Invalid value for AppInstInLiveness")
		}
	}
	return nil
}
