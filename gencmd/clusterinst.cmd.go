// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: clusterinst.proto

package gencmd

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud/cli"
	_ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	distributed_match_engine "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"io"
	math "math"
	"strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
func ClusterInstHideTags(in *edgeproto.ClusterInst) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
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
		in.AllocatedIp = ""
	}
	if _, found := tags["nocmp"]; found {
		in.NodeFlavor = ""
	}
	if _, found := tags["nocmp"]; found {
		in.Status = edgeproto.StatusInfo{}
	}
	if _, found := tags["nocmp"]; found {
		in.ExternalVolumeSize = 0
	}
	if _, found := tags["nocmp"]; found {
		in.ImageName = ""
	}
	if _, found := tags["nocmp"]; found {
		in.MasterNodeFlavor = ""
	}
	if _, found := tags["nocmp"]; found {
		in.SkipCrmCleanupOnFailure = false
	}
	if _, found := tags["nocmp"]; found {
		in.OptRes = ""
	}
	if _, found := tags["nocmp"]; found {
		in.Resources = edgeproto.InfraResources{}
	}
	if _, found := tags["timestamp"]; found {
		in.CreatedAt = distributed_match_engine.Timestamp{}
	}
	if _, found := tags["timestamp"]; found {
		in.UpdatedAt = distributed_match_engine.Timestamp{}
	}
	if _, found := tags["timestamp"]; found {
		in.ReservationEndedAt = distributed_match_engine.Timestamp{}
	}
}

func ClusterInstInfoHideTags(in *edgeproto.ClusterInstInfo) {
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
	for i1 := 0; i1 < len(in.Resources.Vms); i1++ {
		for i2 := 0; i2 < len(in.Resources.Vms[i1].Ipaddresses); i2++ {
		}
		for i2 := 0; i2 < len(in.Resources.Vms[i1].Containers); i2++ {
		}
	}
}

var ClusterInstApiCmd edgeproto.ClusterInstApiClient

var CreateClusterInstCmd = &cli.Command{
	Use:          "CreateClusterInst",
	RequiredArgs: strings.Join(ClusterInstRequiredArgs, " "),
	OptionalArgs: strings.Join(ClusterInstOptionalArgs, " "),
	AliasArgs:    strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:  &ClusterInstSpecialArgs,
	Comments:     ClusterInstComments,
	ReqData:      &edgeproto.ClusterInst{},
	ReplyData:    &edgeproto.Result{},
	Run:          runCreateClusterInst,
}

func runCreateClusterInst(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ClusterInst)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return CreateClusterInst(c, obj)
}

func CreateClusterInst(c *cli.Command, in *edgeproto.ClusterInst) error {
	if ClusterInstApiCmd == nil {
		return fmt.Errorf("ClusterInstApi client not initialized")
	}
	ctx := context.Background()
	stream, err := ClusterInstApiCmd.CreateClusterInst(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("CreateClusterInst failed: %s", errstr)
	}

	objs := make([]*edgeproto.Result, 0)
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
			return fmt.Errorf("CreateClusterInst recv failed: %s", errstr)
		}
		if cli.OutputStream {
			c.WriteOutput(obj, cli.OutputFormat)
			continue
		}
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func CreateClusterInsts(c *cli.Command, data []edgeproto.ClusterInst, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("CreateClusterInst %v\n", data[ii])
		myerr := CreateClusterInst(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteClusterInstCmd = &cli.Command{
	Use:          "DeleteClusterInst",
	RequiredArgs: strings.Join(ClusterInstRequiredArgs, " "),
	OptionalArgs: strings.Join(ClusterInstOptionalArgs, " "),
	AliasArgs:    strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:  &ClusterInstSpecialArgs,
	Comments:     ClusterInstComments,
	ReqData:      &edgeproto.ClusterInst{},
	ReplyData:    &edgeproto.Result{},
	Run:          runDeleteClusterInst,
}

func runDeleteClusterInst(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ClusterInst)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DeleteClusterInst(c, obj)
}

func DeleteClusterInst(c *cli.Command, in *edgeproto.ClusterInst) error {
	if ClusterInstApiCmd == nil {
		return fmt.Errorf("ClusterInstApi client not initialized")
	}
	ctx := context.Background()
	stream, err := ClusterInstApiCmd.DeleteClusterInst(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteClusterInst failed: %s", errstr)
	}

	objs := make([]*edgeproto.Result, 0)
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
			return fmt.Errorf("DeleteClusterInst recv failed: %s", errstr)
		}
		if cli.OutputStream {
			c.WriteOutput(obj, cli.OutputFormat)
			continue
		}
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DeleteClusterInsts(c *cli.Command, data []edgeproto.ClusterInst, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DeleteClusterInst %v\n", data[ii])
		myerr := DeleteClusterInst(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var UpdateClusterInstCmd = &cli.Command{
	Use:          "UpdateClusterInst",
	RequiredArgs: strings.Join(UpdateClusterInstRequiredArgs, " "),
	OptionalArgs: strings.Join(UpdateClusterInstOptionalArgs, " "),
	AliasArgs:    strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:  &ClusterInstSpecialArgs,
	Comments:     ClusterInstComments,
	ReqData:      &edgeproto.ClusterInst{},
	ReplyData:    &edgeproto.Result{},
	Run:          runUpdateClusterInst,
}

func runUpdateClusterInst(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ClusterInst)
	jsonMap, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	obj.Fields = cli.GetSpecifiedFields(jsonMap, c.ReqData, cli.JsonNamespace)
	return UpdateClusterInst(c, obj)
}

func UpdateClusterInst(c *cli.Command, in *edgeproto.ClusterInst) error {
	if ClusterInstApiCmd == nil {
		return fmt.Errorf("ClusterInstApi client not initialized")
	}
	ctx := context.Background()
	stream, err := ClusterInstApiCmd.UpdateClusterInst(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("UpdateClusterInst failed: %s", errstr)
	}

	objs := make([]*edgeproto.Result, 0)
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
			return fmt.Errorf("UpdateClusterInst recv failed: %s", errstr)
		}
		if cli.OutputStream {
			c.WriteOutput(obj, cli.OutputFormat)
			continue
		}
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func UpdateClusterInsts(c *cli.Command, data []edgeproto.ClusterInst, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("UpdateClusterInst %v\n", data[ii])
		myerr := UpdateClusterInst(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowClusterInstCmd = &cli.Command{
	Use:          "ShowClusterInst",
	OptionalArgs: strings.Join(append(ClusterInstRequiredArgs, ClusterInstOptionalArgs...), " "),
	AliasArgs:    strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:  &ClusterInstSpecialArgs,
	Comments:     ClusterInstComments,
	ReqData:      &edgeproto.ClusterInst{},
	ReplyData:    &edgeproto.ClusterInst{},
	Run:          runShowClusterInst,
}

func runShowClusterInst(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ClusterInst)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowClusterInst(c, obj)
}

func ShowClusterInst(c *cli.Command, in *edgeproto.ClusterInst) error {
	if ClusterInstApiCmd == nil {
		return fmt.Errorf("ClusterInstApi client not initialized")
	}
	ctx := context.Background()
	stream, err := ClusterInstApiCmd.ShowClusterInst(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowClusterInst failed: %s", errstr)
	}

	objs := make([]*edgeproto.ClusterInst, 0)
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
			return fmt.Errorf("ShowClusterInst recv failed: %s", errstr)
		}
		ClusterInstHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowClusterInsts(c *cli.Command, data []edgeproto.ClusterInst, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowClusterInst %v\n", data[ii])
		myerr := ShowClusterInst(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DeleteIdleReservableClusterInstsCmd = &cli.Command{
	Use:          "DeleteIdleReservableClusterInsts",
	RequiredArgs: strings.Join(IdleReservableClusterInstsRequiredArgs, " "),
	OptionalArgs: strings.Join(IdleReservableClusterInstsOptionalArgs, " "),
	AliasArgs:    strings.Join(IdleReservableClusterInstsAliasArgs, " "),
	SpecialArgs:  &IdleReservableClusterInstsSpecialArgs,
	Comments:     IdleReservableClusterInstsComments,
	ReqData:      &edgeproto.IdleReservableClusterInsts{},
	ReplyData:    &edgeproto.Result{},
	Run:          runDeleteIdleReservableClusterInsts,
}

func runDeleteIdleReservableClusterInsts(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.IdleReservableClusterInsts)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return DeleteIdleReservableClusterInsts(c, obj)
}

func DeleteIdleReservableClusterInsts(c *cli.Command, in *edgeproto.IdleReservableClusterInsts) error {
	if ClusterInstApiCmd == nil {
		return fmt.Errorf("ClusterInstApi client not initialized")
	}
	ctx := context.Background()
	obj, err := ClusterInstApiCmd.DeleteIdleReservableClusterInsts(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DeleteIdleReservableClusterInsts failed: %s", errstr)
	}
	c.WriteOutput(obj, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func DeleteIdleReservableClusterInstsBatch(c *cli.Command, data *edgeproto.IdleReservableClusterInsts, err *error) {
	if *err != nil || data == nil {
		return
	}
	fmt.Printf("DeleteIdleReservableClusterInsts %v\n", data)
	myerr := DeleteIdleReservableClusterInsts(c, data)
	if myerr != nil {
		*err = myerr
	}
}

var ClusterInstApiCmds = []*cobra.Command{
	CreateClusterInstCmd.GenCmd(),
	DeleteClusterInstCmd.GenCmd(),
	UpdateClusterInstCmd.GenCmd(),
	ShowClusterInstCmd.GenCmd(),
	DeleteIdleReservableClusterInstsCmd.GenCmd(),
}

var ClusterInstInfoApiCmd edgeproto.ClusterInstInfoApiClient

var ShowClusterInstInfoCmd = &cli.Command{
	Use:          "ShowClusterInstInfo",
	OptionalArgs: strings.Join(append(ClusterInstInfoRequiredArgs, ClusterInstInfoOptionalArgs...), " "),
	AliasArgs:    strings.Join(ClusterInstInfoAliasArgs, " "),
	SpecialArgs:  &ClusterInstInfoSpecialArgs,
	Comments:     ClusterInstInfoComments,
	ReqData:      &edgeproto.ClusterInstInfo{},
	ReplyData:    &edgeproto.ClusterInstInfo{},
	Run:          runShowClusterInstInfo,
}

func runShowClusterInstInfo(c *cli.Command, args []string) error {
	if cli.SilenceUsage {
		c.CobraCmd.SilenceUsage = true
	}
	obj := c.ReqData.(*edgeproto.ClusterInstInfo)
	_, err := c.ParseInput(args)
	if err != nil {
		return err
	}
	return ShowClusterInstInfo(c, obj)
}

func ShowClusterInstInfo(c *cli.Command, in *edgeproto.ClusterInstInfo) error {
	if ClusterInstInfoApiCmd == nil {
		return fmt.Errorf("ClusterInstInfoApi client not initialized")
	}
	ctx := context.Background()
	stream, err := ClusterInstInfoApiCmd.ShowClusterInstInfo(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowClusterInstInfo failed: %s", errstr)
	}

	objs := make([]*edgeproto.ClusterInstInfo, 0)
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
			return fmt.Errorf("ShowClusterInstInfo recv failed: %s", errstr)
		}
		ClusterInstInfoHideTags(obj)
		objs = append(objs, obj)
	}
	if len(objs) == 0 {
		return nil
	}
	c.WriteOutput(objs, cli.OutputFormat)
	return nil
}

// this supports "Create" and "Delete" commands on ApplicationData
func ShowClusterInstInfos(c *cli.Command, data []edgeproto.ClusterInstInfo, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowClusterInstInfo %v\n", data[ii])
		myerr := ShowClusterInstInfo(c, &data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ClusterInstInfoApiCmds = []*cobra.Command{
	ShowClusterInstInfoCmd.GenCmd(),
}

var ClusterInstKeyRequiredArgs = []string{}
var ClusterInstKeyOptionalArgs = []string{
	"clusterkey.name",
	"cloudletkey.organization",
	"cloudletkey.name",
	"organization",
}
var ClusterInstKeyAliasArgs = []string{}
var ClusterInstKeyComments = map[string]string{
	"clusterkey.name":          "Cluster name",
	"cloudletkey.organization": "Organization of the cloudlet site",
	"cloudletkey.name":         "Name of the cloudlet",
	"organization":             "Name of Developer organization that this cluster belongs to",
}
var ClusterInstKeySpecialArgs = map[string]string{}
var ClusterInstRequiredArgs = []string{
	"cluster",
	"cloudlet-org",
	"cloudlet",
	"cluster-org",
}
var ClusterInstOptionalArgs = []string{
	"flavor",
	"crmoverride",
	"ipaccess",
	"deployment",
	"nummasters",
	"numnodes",
	"autoscalepolicy",
	"imagename",
	"reservable",
	"sharedvolumesize",
	"skipcrmcleanuponfailure",
	"reservationendedat.seconds",
	"reservationendedat.nanos",
}
var ClusterInstAliasArgs = []string{
	"cluster=key.clusterkey.name",
	"cloudlet-org=key.cloudletkey.organization",
	"cloudlet=key.cloudletkey.name",
	"cluster-org=key.organization",
	"flavor=flavor.name",
}
var ClusterInstComments = map[string]string{
	"fields":                                 "Fields are used for the Update API to specify which fields to apply",
	"cluster":                                "Cluster name",
	"cloudlet-org":                           "Organization of the cloudlet site",
	"cloudlet":                               "Name of the cloudlet",
	"cluster-org":                            "Name of Developer organization that this cluster belongs to",
	"flavor":                                 "Flavor name",
	"liveness":                               "Liveness of instance (see Liveness), one of LivenessUnknown, LivenessStatic, LivenessDynamic, LivenessAutoprov",
	"auto":                                   "Auto is set to true when automatically created by back-end (internal use only)",
	"state":                                  "State of the cluster instance, one of TrackedStateUnknown, NotPresent, CreateRequested, Creating, CreateError, Ready, UpdateRequested, Updating, UpdateError, DeleteRequested, Deleting, DeleteError, DeletePrepare, CrmInitok, CreatingDependencies, DeleteDone",
	"errors":                                 "Any errors trying to create, update, or delete the ClusterInst on the Cloudlet.",
	"crmoverride":                            "Override actions to CRM, one of NoOverride, IgnoreCrmErrors, IgnoreCrm, IgnoreTransientState, IgnoreCrmAndTransientState",
	"ipaccess":                               "IP access type (RootLB Type), one of IpAccessUnknown, IpAccessDedicated, IpAccessShared",
	"allocatedip":                            "Allocated IP for dedicated access",
	"nodeflavor":                             "Cloudlet specific node flavor",
	"deployment":                             "Deployment type (kubernetes or docker)",
	"nummasters":                             "Number of k8s masters (In case of docker deployment, this field is not required)",
	"numnodes":                               "Number of k8s nodes (In case of docker deployment, this field is not required)",
	"externalvolumesize":                     "Size of external volume to be attached to nodes.  This is for the root partition",
	"autoscalepolicy":                        "Auto scale policy name",
	"availabilityzone":                       "Optional Resource AZ if any",
	"imagename":                              "Optional resource specific image to launch",
	"reservable":                             "If ClusterInst is reservable",
	"reservedby":                             "For reservable MobiledgeX ClusterInsts, the current developer tenant",
	"sharedvolumesize":                       "Size of an optional shared volume to be mounted on the master",
	"masternodeflavor":                       "Generic flavor for k8s master VM when worker nodes > 0",
	"skipcrmcleanuponfailure":                "Prevents cleanup of resources on failure within CRM, used for diagnostic purposes",
	"optres":                                 "Optional Resources required by OS flavor if any",
	"resources.vms:#.name":                   "Virtual machine name",
	"resources.vms:#.type":                   "Type can be platform, rootlb, cluster-master, cluster-node, vmapp",
	"resources.vms:#.status":                 "Runtime status of the VM",
	"resources.vms:#.infraflavor":            "Flavor allocated within the cloudlet infrastructure, distinct from the control plane flavor",
	"resources.vms:#.containers:#.name":      "Name of the container",
	"resources.vms:#.containers:#.type":      "Type can be docker or kubernetes",
	"resources.vms:#.containers:#.status":    "Runtime status of the container",
	"resources.vms:#.containers:#.clusterip": "IP within the CNI and is applicable to kubernetes only",
	"resources.vms:#.containers:#.restarts":  "Restart count, applicable to kubernetes only",
}
var ClusterInstSpecialArgs = map[string]string{
	"errors":      "StringArray",
	"fields":      "StringArray",
	"status.msgs": "StringArray",
}
var IdleReservableClusterInstsRequiredArgs = []string{}
var IdleReservableClusterInstsOptionalArgs = []string{
	"idletime",
}
var IdleReservableClusterInstsAliasArgs = []string{}
var IdleReservableClusterInstsComments = map[string]string{
	"idletime": "Idle time (duration)",
}
var IdleReservableClusterInstsSpecialArgs = map[string]string{}
var ClusterInstInfoRequiredArgs = []string{
	"key.clusterkey.name",
	"key.cloudletkey.organization",
	"key.cloudletkey.name",
	"key.organization",
}
var ClusterInstInfoOptionalArgs = []string{
	"notifyid",
	"state",
	"errors",
	"status.tasknumber",
	"status.maxtasks",
	"status.taskname",
	"status.stepname",
	"status.msgcount",
	"status.msgs",
	"resources.vms:#.name",
	"resources.vms:#.type",
	"resources.vms:#.status",
	"resources.vms:#.infraflavor",
	"resources.vms:#.ipaddresses:#.externalip",
	"resources.vms:#.ipaddresses:#.internalip",
	"resources.vms:#.containers:#.name",
	"resources.vms:#.containers:#.type",
	"resources.vms:#.containers:#.status",
	"resources.vms:#.containers:#.clusterip",
	"resources.vms:#.containers:#.restarts",
}
var ClusterInstInfoAliasArgs = []string{}
var ClusterInstInfoComments = map[string]string{
	"fields":                                 "Fields are used for the Update API to specify which fields to apply",
	"key.clusterkey.name":                    "Cluster name",
	"key.cloudletkey.organization":           "Organization of the cloudlet site",
	"key.cloudletkey.name":                   "Name of the cloudlet",
	"key.organization":                       "Name of Developer organization that this cluster belongs to",
	"notifyid":                               "Id of client assigned by server (internal use only)",
	"state":                                  "State of the cluster instance, one of TrackedStateUnknown, NotPresent, CreateRequested, Creating, CreateError, Ready, UpdateRequested, Updating, UpdateError, DeleteRequested, Deleting, DeleteError, DeletePrepare, CrmInitok, CreatingDependencies, DeleteDone",
	"errors":                                 "Any errors trying to create, update, or delete the ClusterInst on the Cloudlet.",
	"resources.vms:#.name":                   "Virtual machine name",
	"resources.vms:#.type":                   "Type can be platform, rootlb, cluster-master, cluster-node, vmapp",
	"resources.vms:#.status":                 "Runtime status of the VM",
	"resources.vms:#.infraflavor":            "Flavor allocated within the cloudlet infrastructure, distinct from the control plane flavor",
	"resources.vms:#.containers:#.name":      "Name of the container",
	"resources.vms:#.containers:#.type":      "Type can be docker or kubernetes",
	"resources.vms:#.containers:#.status":    "Runtime status of the container",
	"resources.vms:#.containers:#.clusterip": "IP within the CNI and is applicable to kubernetes only",
	"resources.vms:#.containers:#.restarts":  "Restart count, applicable to kubernetes only",
}
var ClusterInstInfoSpecialArgs = map[string]string{
	"errors":      "StringArray",
	"fields":      "StringArray",
	"status.msgs": "StringArray",
}
var UpdateClusterInstRequiredArgs = []string{
	"cluster",
	"cloudlet-org",
	"cloudlet",
	"cluster-org",
}
var UpdateClusterInstOptionalArgs = []string{
	"crmoverride",
	"numnodes",
	"autoscalepolicy",
	"skipcrmcleanuponfailure",
	"reservationendedat.seconds",
	"reservationendedat.nanos",
}
