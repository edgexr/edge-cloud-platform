// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app-client.proto

package gencmd

import (
	"context"
	fmt "fmt"
	distributed_match_engine "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	_ "github.com/gogo/googleapis/google/api"
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
var MatchEngineApiCmd distributed_match_engine.MatchEngineApiClient

var FindCloudletCmd = &cli.Command{
	Use:          "FindCloudlet",
	RequiredArgs: strings.Join(FindCloudletRequestRequiredArgs, " "),
	OptionalArgs: strings.Join(FindCloudletRequestOptionalArgs, " "),
	AliasArgs:    strings.Join(FindCloudletRequestAliasArgs, " "),
	SpecialArgs:  &FindCloudletRequestSpecialArgs,
	Comments:     FindCloudletRequestComments,
	ReqData:      &distributed_match_engine.FindCloudletRequest{},
	ReplyData:    &distributed_match_engine.FindCloudletReply{},
	Run:          runFindCloudlet,
}

func runFindCloudlet(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*distributed_match_engine.FindCloudletRequest)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return FindCloudlet(c, obj)
}

func FindCloudlet(c *cli.Command, in *distributed_match_engine.FindCloudletRequest) error {
	if MatchEngineApiCmd == nil {
		return fmt.Errorf("MatchEngineApi client not initialized")
	}
	ctx := context.Background()
	obj, err := MatchEngineApiCmd.FindCloudlet(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("FindCloudlet failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func FindCloudlets(c *cli.Command, data []distributed_match_engine.FindCloudletRequest, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("FindCloudlet %v\n", data[ii])
		myerr := FindCloudlet(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var GetAppInstListCmd = &cli.Command{
	Use:          "GetAppInstList",
	RequiredArgs: strings.Join(AppInstListRequestRequiredArgs, " "),
	OptionalArgs: strings.Join(AppInstListRequestOptionalArgs, " "),
	AliasArgs:    strings.Join(AppInstListRequestAliasArgs, " "),
	SpecialArgs:  &AppInstListRequestSpecialArgs,
	Comments:     AppInstListRequestComments,
	ReqData:      &distributed_match_engine.AppInstListRequest{},
	ReplyData:    &distributed_match_engine.AppInstListReply{},
	Run:          runGetAppInstList,
}

func runGetAppInstList(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*distributed_match_engine.AppInstListRequest)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return GetAppInstList(c, obj)
}

func GetAppInstList(c *cli.Command, in *distributed_match_engine.AppInstListRequest) error {
	if MatchEngineApiCmd == nil {
		return fmt.Errorf("MatchEngineApi client not initialized")
	}
	ctx := context.Background()
	obj, err := MatchEngineApiCmd.GetAppInstList(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("GetAppInstList failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func GetAppInstLists(c *cli.Command, data []distributed_match_engine.AppInstListRequest, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("GetAppInstList %v\n", data[ii])
		myerr := GetAppInstList(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var GetAppOfficialFqdnCmd = &cli.Command{
	Use:          "GetAppOfficialFqdn",
	RequiredArgs: strings.Join(AppOfficialFqdnRequestRequiredArgs, " "),
	OptionalArgs: strings.Join(AppOfficialFqdnRequestOptionalArgs, " "),
	AliasArgs:    strings.Join(AppOfficialFqdnRequestAliasArgs, " "),
	SpecialArgs:  &AppOfficialFqdnRequestSpecialArgs,
	Comments:     AppOfficialFqdnRequestComments,
	ReqData:      &distributed_match_engine.AppOfficialFqdnRequest{},
	ReplyData:    &distributed_match_engine.AppOfficialFqdnReply{},
	Run:          runGetAppOfficialFqdn,
}

func runGetAppOfficialFqdn(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*distributed_match_engine.AppOfficialFqdnRequest)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return GetAppOfficialFqdn(c, obj)
}

func GetAppOfficialFqdn(c *cli.Command, in *distributed_match_engine.AppOfficialFqdnRequest) error {
	if MatchEngineApiCmd == nil {
		return fmt.Errorf("MatchEngineApi client not initialized")
	}
	ctx := context.Background()
	obj, err := MatchEngineApiCmd.GetAppOfficialFqdn(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("GetAppOfficialFqdn failed: %s", errstr)
	}
	c.WriteOutput(c.CobraCmd.OutOrStdout(), obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func GetAppOfficialFqdns(c *cli.Command, data []distributed_match_engine.AppOfficialFqdnRequest, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("GetAppOfficialFqdn %v\n", data[ii])
		myerr := GetAppOfficialFqdn(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var MatchEngineApiCmds = []*cobra.Command{
	FindCloudletCmd.GenCmd(),
	GetAppInstListCmd.GenCmd(),
	GetAppOfficialFqdnCmd.GenCmd(),
}

var FindCloudletRequestRequiredArgs = []string{}
var FindCloudletRequestOptionalArgs = []string{
	"ver",
	"sessioncookie",
	"carriername",
	"gpslocation.latitude",
	"gpslocation.longitude",
	"gpslocation.horizontalaccuracy",
	"gpslocation.verticalaccuracy",
	"gpslocation.altitude",
	"gpslocation.course",
	"gpslocation.speed",
	"gpslocation.timestamp",
	"tags",
}
var FindCloudletRequestAliasArgs = []string{}
var FindCloudletRequestComments = map[string]string{
	"ver":                            "API version _(hidden)_ Reserved for future use",
	"sessioncookie":                  "Session Cookie Session Cookie from RegisterClientRequest",
	"carriername":                    "Carrier Name _(optional)_ By default, all SDKs will automatically fill in this parameter with the MCC+MNC of your current provider. Only override this parameter if you need to filter for a specific carrier on the DME. The DME will filter for App instances that are associated with the specified carrier. If you wish to search for any App Instance on the DME regardless of carrier name, you can input “” to consider all carriers as “Any”.",
	"gpslocation.latitude":           "Latitude in WGS 84 coordinates",
	"gpslocation.longitude":          "Longitude in WGS 84 coordinates",
	"gpslocation.horizontalaccuracy": "Horizontal accuracy (radius in meters)",
	"gpslocation.verticalaccuracy":   "Vertical accuracy (meters)",
	"gpslocation.altitude":           "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"gpslocation.course":             "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"gpslocation.speed":              "Speed (IOS) / velocity (Android) (meters/sec)",
	"gpslocation.timestamp":          "Timestamp",
	"tags":                           "Tags _(optional)_ Vendor specific data",
}
var FindCloudletRequestSpecialArgs = map[string]string{
	"tags": "StringToString",
}
var FindCloudletReplyRequiredArgs = []string{}
var FindCloudletReplyOptionalArgs = []string{
	"ver",
	"status",
	"fqdn",
	"ports:#.proto",
	"ports:#.internalport",
	"ports:#.publicport",
	"ports:#.fqdnprefix",
	"ports:#.endport",
	"ports:#.tls",
	"ports:#.nginx",
	"ports:#.maxpktsize",
	"cloudletlocation.latitude",
	"cloudletlocation.longitude",
	"cloudletlocation.horizontalaccuracy",
	"cloudletlocation.verticalaccuracy",
	"cloudletlocation.altitude",
	"cloudletlocation.course",
	"cloudletlocation.speed",
	"cloudletlocation.timestamp",
	"edgeeventscookie",
	"qosresult",
	"qoserrormsg",
	"tags",
}
var FindCloudletReplyAliasArgs = []string{}
var FindCloudletReplyComments = map[string]string{
	"ver":                                 "API version _(hidden)_ Reserved for future use",
	"status":                              "Status return, one of Unknown, Found, Notfound",
	"fqdn":                                "Fully Qualified Domain Name of the Closest App instance",
	"ports:#.proto":                       "TCP (L4) or UDP (L4) protocol, one of Unknown, Tcp, Udp",
	"ports:#.internalport":                "Container port",
	"ports:#.publicport":                  "Public facing port for TCP/UDP (may be mapped on shared LB reverse proxy)",
	"ports:#.fqdnprefix":                  "FQDN prefix to append to base FQDN in FindCloudlet response. May be empty.",
	"ports:#.endport":                     "A non-zero end port indicates a port range from internal port to end port, inclusive.",
	"ports:#.tls":                         "TLS termination for this port",
	"ports:#.nginx":                       "Use nginx proxy for this port if you really need a transparent proxy (udp only)",
	"ports:#.maxpktsize":                  "Maximum datagram size (udp only)",
	"cloudletlocation.latitude":           "Latitude in WGS 84 coordinates",
	"cloudletlocation.longitude":          "Longitude in WGS 84 coordinates",
	"cloudletlocation.horizontalaccuracy": "Horizontal accuracy (radius in meters)",
	"cloudletlocation.verticalaccuracy":   "Vertical accuracy (meters)",
	"cloudletlocation.altitude":           "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"cloudletlocation.course":             "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"cloudletlocation.speed":              "Speed (IOS) / velocity (Android) (meters/sec)",
	"cloudletlocation.timestamp":          "Timestamp",
	"edgeeventscookie":                    "Session Cookie for specific EdgeEvents for specific AppInst",
	"qosresult":                           "Result of QOS priority session creation attempt, one of NotAttempted, SessionCreated, SessionFailed",
	"qoserrormsg":                         "Error message in case of QOS_SESSION_FAILED",
	"tags":                                "_(optional)_ Vendor specific data",
}
var FindCloudletReplySpecialArgs = map[string]string{
	"tags": "StringToString",
}
var AppInstListRequestRequiredArgs = []string{}
var AppInstListRequestOptionalArgs = []string{
	"ver",
	"sessioncookie",
	"carriername",
	"gpslocation.latitude",
	"gpslocation.longitude",
	"gpslocation.horizontalaccuracy",
	"gpslocation.verticalaccuracy",
	"gpslocation.altitude",
	"gpslocation.course",
	"gpslocation.speed",
	"gpslocation.timestamp",
	"limit",
	"tags",
}
var AppInstListRequestAliasArgs = []string{}
var AppInstListRequestComments = map[string]string{
	"ver":                            "API version _(hidden)_ Reserved for future use",
	"sessioncookie":                  "Session Cookie from RegisterClientRequest",
	"carriername":                    "Carrier Name _(optional)_ By default, all SDKs will automatically fill in this parameter with the MCC+MNC of your current provider. Only override this parameter if you need to filter for a specific carrier on the DME. The DME will filter for App instances that are associated with the specified carrier. If you wish to search for any App Instance on the DME regardless of carrier name, you can input “” to consider all carriers as “Any”.",
	"gpslocation.latitude":           "Latitude in WGS 84 coordinates",
	"gpslocation.longitude":          "Longitude in WGS 84 coordinates",
	"gpslocation.horizontalaccuracy": "Horizontal accuracy (radius in meters)",
	"gpslocation.verticalaccuracy":   "Vertical accuracy (meters)",
	"gpslocation.altitude":           "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"gpslocation.course":             "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"gpslocation.speed":              "Speed (IOS) / velocity (Android) (meters/sec)",
	"gpslocation.timestamp":          "Timestamp",
	"limit":                          "_(optional)_ Limit the number of results, defaults to 3",
	"tags":                           "_(optional)_ Vendor specific data",
}
var AppInstListRequestSpecialArgs = map[string]string{
	"tags": "StringToString",
}
var AppinstanceRequiredArgs = []string{}
var AppinstanceOptionalArgs = []string{
	"appname",
	"appvers",
	"fqdn",
	"ports:#.proto",
	"ports:#.internalport",
	"ports:#.publicport",
	"ports:#.fqdnprefix",
	"ports:#.endport",
	"ports:#.tls",
	"ports:#.nginx",
	"ports:#.maxpktsize",
	"orgname",
	"edgeeventscookie",
}
var AppinstanceAliasArgs = []string{}
var AppinstanceComments = map[string]string{
	"appname":              "App Instance Name",
	"appvers":              "App Instance Version",
	"fqdn":                 "App Instance FQDN",
	"ports:#.proto":        "TCP (L4) or UDP (L4) protocol, one of Unknown, Tcp, Udp",
	"ports:#.internalport": "Container port",
	"ports:#.publicport":   "Public facing port for TCP/UDP (may be mapped on shared LB reverse proxy)",
	"ports:#.fqdnprefix":   "FQDN prefix to append to base FQDN in FindCloudlet response. May be empty.",
	"ports:#.endport":      "A non-zero end port indicates a port range from internal port to end port, inclusive.",
	"ports:#.tls":          "TLS termination for this port",
	"ports:#.nginx":        "Use nginx proxy for this port if you really need a transparent proxy (udp only)",
	"ports:#.maxpktsize":   "Maximum datagram size (udp only)",
	"orgname":              "App Organization Name",
	"edgeeventscookie":     "Session Cookie for specific EdgeEvents for specific AppInst",
}
var AppinstanceSpecialArgs = map[string]string{}
var CloudletLocationRequiredArgs = []string{}
var CloudletLocationOptionalArgs = []string{
	"carriername",
	"cloudletname",
	"gpslocation.latitude",
	"gpslocation.longitude",
	"gpslocation.horizontalaccuracy",
	"gpslocation.verticalaccuracy",
	"gpslocation.altitude",
	"gpslocation.course",
	"gpslocation.speed",
	"gpslocation.timestamp",
	"distance",
	"appinstances:#.appname",
	"appinstances:#.appvers",
	"appinstances:#.fqdn",
	"appinstances:#.ports:#.proto",
	"appinstances:#.ports:#.internalport",
	"appinstances:#.ports:#.publicport",
	"appinstances:#.ports:#.fqdnprefix",
	"appinstances:#.ports:#.endport",
	"appinstances:#.ports:#.tls",
	"appinstances:#.ports:#.nginx",
	"appinstances:#.ports:#.maxpktsize",
	"appinstances:#.orgname",
	"appinstances:#.edgeeventscookie",
}
var CloudletLocationAliasArgs = []string{}
var CloudletLocationComments = map[string]string{
	"carriername":                         "Cloudlet Organization Name",
	"cloudletname":                        "Cloudlet Name",
	"gpslocation.latitude":                "Latitude in WGS 84 coordinates",
	"gpslocation.longitude":               "Longitude in WGS 84 coordinates",
	"gpslocation.horizontalaccuracy":      "Horizontal accuracy (radius in meters)",
	"gpslocation.verticalaccuracy":        "Vertical accuracy (meters)",
	"gpslocation.altitude":                "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"gpslocation.course":                  "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"gpslocation.speed":                   "Speed (IOS) / velocity (Android) (meters/sec)",
	"gpslocation.timestamp":               "Timestamp",
	"distance":                            "Distance of cloudlet vs loc in request",
	"appinstances:#.appname":              "App Instance Name",
	"appinstances:#.appvers":              "App Instance Version",
	"appinstances:#.fqdn":                 "App Instance FQDN",
	"appinstances:#.ports:#.proto":        "TCP (L4) or UDP (L4) protocol, one of Unknown, Tcp, Udp",
	"appinstances:#.ports:#.internalport": "Container port",
	"appinstances:#.ports:#.publicport":   "Public facing port for TCP/UDP (may be mapped on shared LB reverse proxy)",
	"appinstances:#.ports:#.fqdnprefix":   "FQDN prefix to append to base FQDN in FindCloudlet response. May be empty.",
	"appinstances:#.ports:#.endport":      "A non-zero end port indicates a port range from internal port to end port, inclusive.",
	"appinstances:#.ports:#.tls":          "TLS termination for this port",
	"appinstances:#.ports:#.nginx":        "Use nginx proxy for this port if you really need a transparent proxy (udp only)",
	"appinstances:#.ports:#.maxpktsize":   "Maximum datagram size (udp only)",
	"appinstances:#.orgname":              "App Organization Name",
	"appinstances:#.edgeeventscookie":     "Session Cookie for specific EdgeEvents for specific AppInst",
}
var CloudletLocationSpecialArgs = map[string]string{}
var AppInstListReplyRequiredArgs = []string{}
var AppInstListReplyOptionalArgs = []string{
	"ver",
	"status",
	"cloudlets:#.carriername",
	"cloudlets:#.cloudletname",
	"cloudlets:#.gpslocation.latitude",
	"cloudlets:#.gpslocation.longitude",
	"cloudlets:#.gpslocation.horizontalaccuracy",
	"cloudlets:#.gpslocation.verticalaccuracy",
	"cloudlets:#.gpslocation.altitude",
	"cloudlets:#.gpslocation.course",
	"cloudlets:#.gpslocation.speed",
	"cloudlets:#.gpslocation.timestamp",
	"cloudlets:#.distance",
	"cloudlets:#.appinstances:#.appname",
	"cloudlets:#.appinstances:#.appvers",
	"cloudlets:#.appinstances:#.fqdn",
	"cloudlets:#.appinstances:#.ports:#.proto",
	"cloudlets:#.appinstances:#.ports:#.internalport",
	"cloudlets:#.appinstances:#.ports:#.publicport",
	"cloudlets:#.appinstances:#.ports:#.fqdnprefix",
	"cloudlets:#.appinstances:#.ports:#.endport",
	"cloudlets:#.appinstances:#.ports:#.tls",
	"cloudlets:#.appinstances:#.ports:#.nginx",
	"cloudlets:#.appinstances:#.ports:#.maxpktsize",
	"cloudlets:#.appinstances:#.orgname",
	"cloudlets:#.appinstances:#.edgeeventscookie",
	"tags",
}
var AppInstListReplyAliasArgs = []string{}
var AppInstListReplyComments = map[string]string{
	"ver":                                             "API version _(hidden)_ Reserved for future use",
	"status":                                          ", one of Undefined, Success, Fail",
	"cloudlets:#.carriername":                         "Cloudlet Organization Name",
	"cloudlets:#.cloudletname":                        "Cloudlet Name",
	"cloudlets:#.gpslocation.latitude":                "Latitude in WGS 84 coordinates",
	"cloudlets:#.gpslocation.longitude":               "Longitude in WGS 84 coordinates",
	"cloudlets:#.gpslocation.horizontalaccuracy":      "Horizontal accuracy (radius in meters)",
	"cloudlets:#.gpslocation.verticalaccuracy":        "Vertical accuracy (meters)",
	"cloudlets:#.gpslocation.altitude":                "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"cloudlets:#.gpslocation.course":                  "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"cloudlets:#.gpslocation.speed":                   "Speed (IOS) / velocity (Android) (meters/sec)",
	"cloudlets:#.gpslocation.timestamp":               "Timestamp",
	"cloudlets:#.distance":                            "Distance of cloudlet vs loc in request",
	"cloudlets:#.appinstances:#.appname":              "App Instance Name",
	"cloudlets:#.appinstances:#.appvers":              "App Instance Version",
	"cloudlets:#.appinstances:#.fqdn":                 "App Instance FQDN",
	"cloudlets:#.appinstances:#.ports:#.proto":        "TCP (L4) or UDP (L4) protocol, one of Unknown, Tcp, Udp",
	"cloudlets:#.appinstances:#.ports:#.internalport": "Container port",
	"cloudlets:#.appinstances:#.ports:#.publicport":   "Public facing port for TCP/UDP (may be mapped on shared LB reverse proxy)",
	"cloudlets:#.appinstances:#.ports:#.fqdnprefix":   "FQDN prefix to append to base FQDN in FindCloudlet response. May be empty.",
	"cloudlets:#.appinstances:#.ports:#.endport":      "A non-zero end port indicates a port range from internal port to end port, inclusive.",
	"cloudlets:#.appinstances:#.ports:#.tls":          "TLS termination for this port",
	"cloudlets:#.appinstances:#.ports:#.nginx":        "Use nginx proxy for this port if you really need a transparent proxy (udp only)",
	"cloudlets:#.appinstances:#.ports:#.maxpktsize":   "Maximum datagram size (udp only)",
	"cloudlets:#.appinstances:#.orgname":              "App Organization Name",
	"cloudlets:#.appinstances:#.edgeeventscookie":     "Session Cookie for specific EdgeEvents for specific AppInst",
	"tags": "_(optional)_ Vendor specific data",
}
var AppInstListReplySpecialArgs = map[string]string{
	"tags": "StringToString",
}
var AppOfficialFqdnRequestRequiredArgs = []string{}
var AppOfficialFqdnRequestOptionalArgs = []string{
	"ver",
	"sessioncookie",
	"gpslocation.latitude",
	"gpslocation.longitude",
	"gpslocation.horizontalaccuracy",
	"gpslocation.verticalaccuracy",
	"gpslocation.altitude",
	"gpslocation.course",
	"gpslocation.speed",
	"gpslocation.timestamp",
	"tags",
}
var AppOfficialFqdnRequestAliasArgs = []string{}
var AppOfficialFqdnRequestComments = map[string]string{
	"ver":                            "API version _(hidden)_ Reserved for future use",
	"sessioncookie":                  "Session Cookie from RegisterClientRequest",
	"gpslocation.latitude":           "Latitude in WGS 84 coordinates",
	"gpslocation.longitude":          "Longitude in WGS 84 coordinates",
	"gpslocation.horizontalaccuracy": "Horizontal accuracy (radius in meters)",
	"gpslocation.verticalaccuracy":   "Vertical accuracy (meters)",
	"gpslocation.altitude":           "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"gpslocation.course":             "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"gpslocation.speed":              "Speed (IOS) / velocity (Android) (meters/sec)",
	"gpslocation.timestamp":          "Timestamp",
	"tags":                           "_(optional)_ Vendor specific data",
}
var AppOfficialFqdnRequestSpecialArgs = map[string]string{
	"tags": "StringToString",
}
var AppOfficialFqdnReplyRequiredArgs = []string{}
var AppOfficialFqdnReplyOptionalArgs = []string{
	"ver",
	"appofficialfqdn",
	"clienttoken",
	"status",
	"ports:#.proto",
	"ports:#.internalport",
	"ports:#.publicport",
	"ports:#.fqdnprefix",
	"ports:#.endport",
	"ports:#.tls",
	"ports:#.nginx",
	"ports:#.maxpktsize",
	"tags",
}
var AppOfficialFqdnReplyAliasArgs = []string{}
var AppOfficialFqdnReplyComments = map[string]string{
	"ver":                  "API version _(hidden)_ Reserved for future use",
	"appofficialfqdn":      "The FQDN to which the app is reached independent of the edge",
	"clienttoken":          "Tokenized client data",
	"status":               "Status of the reply, one of Undefined, Success, Fail",
	"ports:#.proto":        "TCP (L4) or UDP (L4) protocol, one of Unknown, Tcp, Udp",
	"ports:#.internalport": "Container port",
	"ports:#.publicport":   "Public facing port for TCP/UDP (may be mapped on shared LB reverse proxy)",
	"ports:#.fqdnprefix":   "FQDN prefix to append to base FQDN in FindCloudlet response. May be empty.",
	"ports:#.endport":      "A non-zero end port indicates a port range from internal port to end port, inclusive.",
	"ports:#.tls":          "TLS termination for this port",
	"ports:#.nginx":        "Use nginx proxy for this port if you really need a transparent proxy (udp only)",
	"ports:#.maxpktsize":   "Maximum datagram size (udp only)",
	"tags":                 "_(optional)_ Vendor specific data",
}
var AppOfficialFqdnReplySpecialArgs = map[string]string{
	"tags": "StringToString",
}
var ClientEdgeEventRequiredArgs = []string{}
var ClientEdgeEventOptionalArgs = []string{
	"sessioncookie",
	"edgeeventscookie",
	"eventtype",
	"gpslocation.latitude",
	"gpslocation.longitude",
	"gpslocation.horizontalaccuracy",
	"gpslocation.verticalaccuracy",
	"gpslocation.altitude",
	"gpslocation.course",
	"gpslocation.speed",
	"gpslocation.timestamp",
	"samples:#.value",
	"samples:#.timestamp",
	"samples:#.tags",
	"deviceinfostatic.deviceos",
	"deviceinfostatic.devicemodel",
	"deviceinfodynamic.datanetworktype",
	"deviceinfodynamic.signalstrength",
	"deviceinfodynamic.carriername",
	"customevent",
	"tags",
}
var ClientEdgeEventAliasArgs = []string{}
var ClientEdgeEventComments = map[string]string{
	"sessioncookie":                     "Session Cookie from RegisterClientReply",
	"edgeeventscookie":                  "Session Cookie from FindCloudletReply",
	"eventtype":                         ", one of Unknown, InitConnection, TerminateConnection, LatencySamples, LocationUpdate, CustomEvent",
	"gpslocation.latitude":              "Latitude in WGS 84 coordinates",
	"gpslocation.longitude":             "Longitude in WGS 84 coordinates",
	"gpslocation.horizontalaccuracy":    "Horizontal accuracy (radius in meters)",
	"gpslocation.verticalaccuracy":      "Vertical accuracy (meters)",
	"gpslocation.altitude":              "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"gpslocation.course":                "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"gpslocation.speed":                 "Speed (IOS) / velocity (Android) (meters/sec)",
	"gpslocation.timestamp":             "Timestamp",
	"samples:#.value":                   "Latency value",
	"samples:#.timestamp":               "Timestamp",
	"samples:#.tags":                    "_(optional)_ Vendor specific data",
	"deviceinfostatic.deviceos":         "Android or iOS",
	"deviceinfostatic.devicemodel":      "Device model",
	"deviceinfodynamic.datanetworktype": "LTE, 5G, etc.",
	"deviceinfodynamic.signalstrength":  "Device signal strength",
	"deviceinfodynamic.carriername":     "Carrier name (can be different from cloudlet org if using )",
	"customevent":                       "Custom event specified by the application",
	"tags":                              "_(optional)_ Vendor specific data",
}
var ClientEdgeEventSpecialArgs = map[string]string{
	"samples:#.tags": "StringToString",
	"tags":           "StringToString",
}
var ServerEdgeEventRequiredArgs = []string{}
var ServerEdgeEventOptionalArgs = []string{
	"eventtype",
	"cloudletstate",
	"maintenancestate",
	"healthcheck",
	"statistics.avg",
	"statistics.min",
	"statistics.max",
	"statistics.stddev",
	"statistics.variance",
	"statistics.numsamples",
	"statistics.timestamp",
	"newcloudlet.ver",
	"newcloudlet.status",
	"newcloudlet.fqdn",
	"newcloudlet.ports:#.proto",
	"newcloudlet.ports:#.internalport",
	"newcloudlet.ports:#.publicport",
	"newcloudlet.ports:#.fqdnprefix",
	"newcloudlet.ports:#.endport",
	"newcloudlet.ports:#.tls",
	"newcloudlet.ports:#.nginx",
	"newcloudlet.ports:#.maxpktsize",
	"newcloudlet.cloudletlocation.latitude",
	"newcloudlet.cloudletlocation.longitude",
	"newcloudlet.cloudletlocation.horizontalaccuracy",
	"newcloudlet.cloudletlocation.verticalaccuracy",
	"newcloudlet.cloudletlocation.altitude",
	"newcloudlet.cloudletlocation.course",
	"newcloudlet.cloudletlocation.speed",
	"newcloudlet.cloudletlocation.timestamp",
	"newcloudlet.edgeeventscookie",
	"newcloudlet.qosresult",
	"newcloudlet.qoserrormsg",
	"newcloudlet.tags",
	"errormsg",
	"tags",
}
var ServerEdgeEventAliasArgs = []string{}
var ServerEdgeEventComments = map[string]string{
	"eventtype":                                       ", one of Unknown, InitConnection, LatencyRequest, LatencyProcessed, CloudletState, CloudletMaintenance, AppinstHealth, CloudletUpdate, Error",
	"cloudletstate":                                   "Cloudlet state information if cloudlet state is not CLOUDLET_STATE_READY, one of Unknown, Errors, Ready, Offline, NotPresent, Init, Upgrade, NeedSync",
	"maintenancestate":                                "Cloudlet maintenance state information if maintenance state is not NORMAL_OPERATION, one of NormalOperation, MaintenanceStart, MaintenanceStartNoFailover",
	"healthcheck":                                     "AppInst health state information if health check is not HEALTH_CHECK_OK, one of Unknown, RootlbOffline, ServerFail, Ok, CloudletOffline",
	"statistics.avg":                                  "Average",
	"statistics.min":                                  "Minimum",
	"statistics.max":                                  "Maximum",
	"statistics.stddev":                               "Square root of unbiased variance",
	"statistics.variance":                             "Unbiased variance",
	"statistics.numsamples":                           "Number of samples to create stats",
	"statistics.timestamp":                            "Timestamp",
	"newcloudlet.ver":                                 "API version _(hidden)_ Reserved for future use",
	"newcloudlet.status":                              "Status return, one of Unknown, Found, Notfound",
	"newcloudlet.fqdn":                                "Fully Qualified Domain Name of the Closest App instance",
	"newcloudlet.ports:#.proto":                       "TCP (L4) or UDP (L4) protocol, one of Unknown, Tcp, Udp",
	"newcloudlet.ports:#.internalport":                "Container port",
	"newcloudlet.ports:#.publicport":                  "Public facing port for TCP/UDP (may be mapped on shared LB reverse proxy)",
	"newcloudlet.ports:#.fqdnprefix":                  "FQDN prefix to append to base FQDN in FindCloudlet response. May be empty.",
	"newcloudlet.ports:#.endport":                     "A non-zero end port indicates a port range from internal port to end port, inclusive.",
	"newcloudlet.ports:#.tls":                         "TLS termination for this port",
	"newcloudlet.ports:#.nginx":                       "Use nginx proxy for this port if you really need a transparent proxy (udp only)",
	"newcloudlet.ports:#.maxpktsize":                  "Maximum datagram size (udp only)",
	"newcloudlet.cloudletlocation.latitude":           "Latitude in WGS 84 coordinates",
	"newcloudlet.cloudletlocation.longitude":          "Longitude in WGS 84 coordinates",
	"newcloudlet.cloudletlocation.horizontalaccuracy": "Horizontal accuracy (radius in meters)",
	"newcloudlet.cloudletlocation.verticalaccuracy":   "Vertical accuracy (meters)",
	"newcloudlet.cloudletlocation.altitude":           "On android only lat and long are guaranteed to be supplied Altitude in meters",
	"newcloudlet.cloudletlocation.course":             "Course (IOS) / bearing (Android) (degrees east relative to true north)",
	"newcloudlet.cloudletlocation.speed":              "Speed (IOS) / velocity (Android) (meters/sec)",
	"newcloudlet.cloudletlocation.timestamp":          "Timestamp",
	"newcloudlet.edgeeventscookie":                    "Session Cookie for specific EdgeEvents for specific AppInst",
	"newcloudlet.qosresult":                           "Result of QOS priority session creation attempt, one of NotAttempted, SessionCreated, SessionFailed",
	"newcloudlet.qoserrormsg":                         "Error message in case of QOS_SESSION_FAILED",
	"newcloudlet.tags":                                "_(optional)_ Vendor specific data",
	"errormsg":                                        "Error message if event_type is EVENT_ERROR",
	"tags":                                            "_(optional)_ Vendor specific data",
}
var ServerEdgeEventSpecialArgs = map[string]string{
	"newcloudlet.tags": "StringToString",
	"tags":             "StringToString",
}
