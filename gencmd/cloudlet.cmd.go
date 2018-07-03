// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudlet.proto

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
var CloudletApiCmd edgeproto.CloudletApiClient
var CloudletIn edgeproto.Cloudlet
var CloudletFlagSet = pflag.NewFlagSet("Cloudlet", pflag.ExitOnError)
var CloudletStateStrings = []string{
	"Unknown",
	"ConfiguringOpenstack",
	"ConfiguringKubernetes",
	"Ready",
}

func CloudletKeySlicer(in *edgeproto.CloudletKey) []string {
	s := make([]string, 0, 2)
	s = append(s, in.OperatorKey.Name)
	s = append(s, in.Name)
	return s
}

func CloudletKeyHeaderSlicer() []string {
	s := make([]string, 0, 2)
	s = append(s, "OperatorKey-Name")
	s = append(s, "Name")
	return s
}

func CloudletSlicer(in *edgeproto.Cloudlet) []string {
	s := make([]string, 0, 4)
	if in.Fields == nil {
		in.Fields = make([]string, 1)
	}
	s = append(s, in.Fields[0])
	s = append(s, in.Key.OperatorKey.Name)
	s = append(s, in.Key.Name)
	s = append(s, in.AccessUri)
	s = append(s, strconv.FormatFloat(float64(in.Location.Lat), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Location.Long), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Location.HorizontalAccuracy), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Location.VerticalAccuracy), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Location.Altitude), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Location.Course), 'e', -1, 32))
	s = append(s, strconv.FormatFloat(float64(in.Location.Speed), 'e', -1, 32))
	if in.Location.Timestamp == nil {
		in.Location.Timestamp = &google_protobuf.Timestamp{}
	}
	_Location_TimestampTime := time.Unix(in.Location.Timestamp.Seconds, int64(in.Location.Timestamp.Nanos))
	s = append(s, _Location_TimestampTime.String())
	return s
}

func CloudletHeaderSlicer() []string {
	s := make([]string, 0, 4)
	s = append(s, "Fields")
	s = append(s, "Key-OperatorKey-Name")
	s = append(s, "Key-Name")
	s = append(s, "AccessUri")
	s = append(s, "Location-Lat")
	s = append(s, "Location-Long")
	s = append(s, "Location-HorizontalAccuracy")
	s = append(s, "Location-VerticalAccuracy")
	s = append(s, "Location-Altitude")
	s = append(s, "Location-Course")
	s = append(s, "Location-Speed")
	s = append(s, "Location-Timestamp")
	return s
}

func CloudletInfoSlicer(in *edgeproto.CloudletInfo) []string {
	s := make([]string, 0, 4)
	s = append(s, in.Key.OperatorKey.Name)
	s = append(s, in.Key.Name)
	s = append(s, edgeproto.CloudletState_name[int32(in.State)])
	s = append(s, strconv.FormatUint(uint64(in.NotifyId), 10))
	s = append(s, strconv.FormatUint(uint64(in.Resources), 10))
	return s
}

func CloudletInfoHeaderSlicer() []string {
	s := make([]string, 0, 4)
	s = append(s, "Key-OperatorKey-Name")
	s = append(s, "Key-Name")
	s = append(s, "State")
	s = append(s, "NotifyId")
	s = append(s, "Resources")
	return s
}

var CreateCloudletCmd = &cobra.Command{
	Use: "CreateCloudlet",
	Run: func(cmd *cobra.Command, args []string) {
		if CloudletApiCmd == nil {
			fmt.Println("CloudletApi client not initialized")
			return
		}
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		objs, err := CloudletApiCmd.CreateCloudlet(ctx, &CloudletIn)
		cancel()
		if err != nil {
			fmt.Println("CreateCloudlet failed: ", err)
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

var DeleteCloudletCmd = &cobra.Command{
	Use: "DeleteCloudlet",
	Run: func(cmd *cobra.Command, args []string) {
		if CloudletApiCmd == nil {
			fmt.Println("CloudletApi client not initialized")
			return
		}
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		objs, err := CloudletApiCmd.DeleteCloudlet(ctx, &CloudletIn)
		cancel()
		if err != nil {
			fmt.Println("DeleteCloudlet failed: ", err)
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

var UpdateCloudletCmd = &cobra.Command{
	Use: "UpdateCloudlet",
	Run: func(cmd *cobra.Command, args []string) {
		if CloudletApiCmd == nil {
			fmt.Println("CloudletApi client not initialized")
			return
		}
		var err error
		CloudletSetFields()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		objs, err := CloudletApiCmd.UpdateCloudlet(ctx, &CloudletIn)
		cancel()
		if err != nil {
			fmt.Println("UpdateCloudlet failed: ", err)
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

var ShowCloudletCmd = &cobra.Command{
	Use: "ShowCloudlet",
	Run: func(cmd *cobra.Command, args []string) {
		if CloudletApiCmd == nil {
			fmt.Println("CloudletApi client not initialized")
			return
		}
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stream, err := CloudletApiCmd.ShowCloudlet(ctx, &CloudletIn)
		if err != nil {
			fmt.Println("ShowCloudlet failed: ", err)
			return
		}
		objs := make([]*edgeproto.Cloudlet, 0)
		for {
			obj, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println("ShowCloudlet recv failed: ", err)
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
			fmt.Fprintln(output, strings.Join(CloudletHeaderSlicer(), "\t"))
			for _, obj := range objs {
				fmt.Fprintln(output, strings.Join(CloudletSlicer(obj), "\t"))
			}
			output.Flush()
		}
	},
}

var CloudletApiCmds = []*cobra.Command{
	CreateCloudletCmd,
	DeleteCloudletCmd,
	UpdateCloudletCmd,
	ShowCloudletCmd,
}

func init() {
	CloudletFlagSet.StringVar(&CloudletIn.Key.OperatorKey.Name, "key-operatorkey-name", "", "Key.OperatorKey.Name")
	CloudletFlagSet.StringVar(&CloudletIn.Key.Name, "key-name", "", "Key.Name")
	CloudletFlagSet.StringVar(&CloudletIn.AccessUri, "accessuri", "", "AccessUri")
	CloudletFlagSet.Float64Var(&CloudletIn.Location.Lat, "location-lat", 0, "Location.Lat")
	CloudletFlagSet.Float64Var(&CloudletIn.Location.Long, "location-long", 0, "Location.Long")
	CloudletFlagSet.Float64Var(&CloudletIn.Location.Altitude, "location-altitude", 0, "Location.Altitude")
	CreateCloudletCmd.Flags().AddFlagSet(CloudletFlagSet)
	DeleteCloudletCmd.Flags().AddFlagSet(CloudletFlagSet)
	UpdateCloudletCmd.Flags().AddFlagSet(CloudletFlagSet)
	ShowCloudletCmd.Flags().AddFlagSet(CloudletFlagSet)
}

func CloudletSetFields() {
	CloudletIn.Fields = make([]string, 0)
	if CloudletFlagSet.Lookup("key-operatorkey-name").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "2.1.1")
	}
	if CloudletFlagSet.Lookup("key-name").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "2.2")
	}
	if CloudletFlagSet.Lookup("accessuri").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "4")
	}
	if CloudletFlagSet.Lookup("location-lat").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.1")
	}
	if CloudletFlagSet.Lookup("location-long").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.2")
	}
	if CloudletFlagSet.Lookup("location-horizontalaccuracy").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.3")
	}
	if CloudletFlagSet.Lookup("location-verticalaccuracy").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.4")
	}
	if CloudletFlagSet.Lookup("location-altitude").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.5")
	}
	if CloudletFlagSet.Lookup("location-course").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.6")
	}
	if CloudletFlagSet.Lookup("location-speed").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.7")
	}
	if CloudletFlagSet.Lookup("location-timestamp-seconds").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.8.1")
	}
	if CloudletFlagSet.Lookup("location-timestamp-nanos").Changed {
		CloudletIn.Fields = append(CloudletIn.Fields, "5.8.2")
	}
}
