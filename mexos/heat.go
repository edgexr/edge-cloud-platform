package mexos

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/mobiledgex/edge-cloud/vmspec"
)

type VMParams struct {
	VMName                   string
	FlavorName               string
	ExternalVolumeSize       uint64
	SharedVolumeSize         uint64
	ImageName                string
	ApplicationSecurityGroup string // access to application ports for VM or RootLB
	CloudletSecurityGroup    string // SSH access to RootLB for OAM/CRM
	NetworkName              string
	SubnetName               string
	VnicType                 string
	MEXRouterIP              string
	GatewayIP                string
	FloatingIPAddressID      string
	AuthPublicKey            string
	AccessPorts              []util.PortSpec
	DeploymentManifest       string
	Command                  string
	IsRootLB                 bool
	IsInternal               bool
	AvailabilityZone         string
}

type VMParamsOp func(vmp *VMParams) error

type DeploymentType string

const (
	RootLBVMDeployment   DeploymentType = "mexrootlb"
	UserVMDeployment     DeploymentType = "mexuservm"
	PlatformVMDeployment DeploymentType = "mexplatformvm"
)

var heatStackLock sync.Mutex
var heatCreate string = "CREATE"
var heatUpdate string = "UPDATE"
var heatDelete string = "DELETE"
var vmCloudConfig = `#cloud-config
bootcmd:
 - echo MOBILEDGEX CLOUD CONFIG START
 - echo 'APT::Periodic::Enable "0";' > /etc/apt/apt.conf.d/10cloudinit-disable
 - apt-get -y purge update-notifier-common ubuntu-release-upgrader-core landscape-common unattended-upgrades
 - echo "Removed APT and Ubuntu extra packages" | systemd-cat
ssh_authorized_keys:
 - ssh-rsa dummmy-ssh-rsa-data+tr1k4DDfoOrkGMj3X/I2zXZ3U+pDPearVFbczCByPU0dqs16TWikxDoCCxJRGeeUl7duzD9a65bI8Jl+zpfQV+I7OPa81P5/fw15lTzT4+F9MhhOUVJ4PFfD+d6/BLnlUfZ94nZlvSYnT+GoZ8xTAstM7+6pvvvHtaHoV4YqRf5CelbWAQ162XNa9/pW5v/RKDrt203/JEk3e70tzx9KAfSw2vuO1QepkCZAdM9rQoCd ubuntu@registry
chpasswd: { expire: False }
ssh_pwauth: False
timezone: UTC
runcmd:
 - [ echo, MOBILEDGEX, doing, ifconfig ]
 - [ ifconfig, -a ]`

// vmCloudConfigShareMount is appended optionally to vmCloudConfig.   It assumes
// the end of vmCloudConfig is runcmd
var vmCloudConfigShareMount = `
 - chown nobody:nogroup /share
 - chmod 777 /share 
 - echo "/share *(rw,sync,no_subtree_check,no_root_squash)" >> /etc/exports
 - exportfs -a
 - echo "showing exported filesystems"
 - exportfs
disk_setup:
   /dev/vdb:
     table_type: 'gpt'
     overwrite: true
     layout: true
fs_setup:
- label: share_fs
  filesystem: 'ext4'
  device: /dev/vdb
  partition: auto
  overwrite: true
mounts:
- [ "/dev/vdb1", "/share" ]`

// This is the resources part of a template for a VM. It is for use within another template
// the parameters under VMP can come from either a standalone struture (VM Create) or a cluster (for rootLB)
var vmTemplateResources = `
  {{if .ExternalVolumeSize}}
   {{.VMName}}-vol:
      type: OS::Cinder::Volume
      properties:
         name: {{.VMName}}-vol
         image: {{.ImageName}}
         size: {{.ExternalVolumeSize}}
  {{- end }}

   vm_security_group:
       type: OS::Neutron::SecurityGroup
       properties:
          name: {{.ApplicationSecurityGroup}}
          rules:
           - direction: egress
          {{range .AccessPorts}}
           - remote_ip_prefix: 0.0.0.0/0
             protocol: {{.Proto}}
             port_range_min: {{.Port}}
             port_range_max: {{.Port}}
          {{end}}

   {{.VMName}}:
      type: OS::Nova::Server
      properties:
         name: 
            {{.VMName}}
       {{if .ExternalVolumeSize}}
         block_device_mapping: [{ device_name: "vda", volume_id: { get_resource: {{.VMName}}-vol }, delete_on_termination: "false" }]
       {{else}}
         image: {{.ImageName}}
       {{- end}}
        {{if not .FloatingIPAddressID}}
         security_groups:
           - { get_resource: vm_security_group }
          {{if .CloudletSecurityGroup}}
           - {{ .CloudletSecurityGroup}}
          {{- end}}
        {{- end}}
         flavor: {{.FlavorName}}
         {{if .AvailabilityZone}}
           availabilityzone:{{.AvailabilityZone}}
         {{- end}}
        {{if .AuthPublicKey}} key_name: { get_resource: ssh_key_pair } {{- end}}
         config_drive: true       
         user_data_format: RAW
         networks:
        {{if .FloatingIPAddressID}}
          - port: { get_resource: vm-port }
        {{else}}
          - network: {{.NetworkName}}
        {{- end}}
        {{if .IsRootLB}}
         metadata:
            skipk8s: yes
            role: mex-agent-node 
            edgeproxy: {{.GatewayIP}}
            mex-flavor: {{.FlavorName}}
           {{if .MEXRouterIP}}
            privaterouter: {{.MEXRouterIP}}
           {{- end}}
        {{- end}}
        {{if .IsInternal}}
         user_data: |
` + reindent(vmCloudConfig, 12) + `
        {{- end}}
        {{if .DeploymentManifest}}
         user_data: |
{{ Indent .DeploymentManifest 13 }}
        {{- end}}
        {{if .Command}}
         user_data: |
            #cloud-config
            runcmd:
             - {{.Command}}
        {{- end}}
  {{if .AuthPublicKey}}
   ssh_key_pair:
       type: OS::Nova::KeyPair
       properties:
          name: {{.VMName}}-ssh-keypair
          public_key: "{{.AuthPublicKey}}"
  {{- end}}
  {{if .FloatingIPAddressID}}
   vm-port:
       type: OS::Neutron::Port
       properties:
           name: {{.VMName}}-port
          {{if .VnicType}}
           binding:vnic_type: {{.VnicType}}
          {{- end}}
           network_id: {{.NetworkName}}
           fixed_ips: 
            - subnet_id: {{.SubnetName}}
           security_groups:
            - { get_resource: vm_security_group }
           {{if .CloudletSecurityGroup}}
            - {{ .CloudletSecurityGroup}}
           {{- end}}
   floatingip:
       type: OS::Neutron::FloatingIPAssociation
       properties:
          floatingip_id: {{.FloatingIPAddressID}}
          port_id: { get_resource: vm-port }
  {{- end}}`

var VmTemplate = `
heat_template_version: 2016-10-14
description: Create a VM
resources:
` + vmTemplateResources

// ClusterNode is a k8s node
type ClusterNode struct {
	NodeName string
	NodeIP   string
}

// ClusterParams has the info needed to populate the heat template
type ClusterParams struct {
	NodeFlavor            string
	ImageName             string
	MEXRouterName         string
	MEXNetworkName        string
	VnicType              string
	ClusterName           string
	CIDR                  string
	GatewayIP             string
	MasterIP              string
	RootLBConnectToSubnet string
	RootLBPortName        string
	NetworkType           string
	RouterSecurityGroup   string // used for internal comms only if the OpenStack router is present
	DNSServers            []string
	Nodes                 []ClusterNode
	*VMParams             //rootlb
}

var k8sClusterTemplate = `
heat_template_version: 2016-10-14
description: Create a cluster

resources:
   k8s-subnet:
      type: OS::Neutron::Subnet
      properties:
        cidr: {{.CIDR}}
        network: mex-k8s-net-1
        gateway_ip: {{.GatewayIP}}
        enable_dhcp: false
        dns_nameservers:
       {{range .DNSServers}}
         - {{.}}
       {{end}}
        name: 
           mex-k8s-subnet-{{.ClusterName}}
  {{if .RootLBConnectToSubnet}}
   rootlb-port:
      type: OS::Neutron::Port
      properties:
         name: {{.RootLBPortName}}
         network_id: mex-k8s-net-1
         fixed_ips:
          - subnet: { get_resource: k8s-subnet}
            ip_address: {{.GatewayIP}}
         port_security_enabled: false
  {{- end}}
  {{if .MEXRouterName}}
   router-port:
       type: OS::Neutron::Port
       properties:
          name: mex-k8s-subnet-{{.ClusterName}}
          network_id: mex-k8s-net-1
          fixed_ips:
          - subnet: { get_resource: k8s-subnet}
            ip_address: {{.GatewayIP}}
          security_groups:
           - {{.RouterSecurityGroup}}

   router-interface:
      type: OS::Neutron::RouterInterface
      properties:
         router:  {{.MEXRouterName}}
         port: { get_resource: router-port }

  {{- end}}
   k8s-master-port:
      type: OS::Neutron::Port
      properties:
         name: k8s-master-port
        {{if .VnicType}}
         binding:vnic_type: {{.VnicType}}
        {{- end}}
         network_id: {{.MEXNetworkName}}
         fixed_ips:
          - subnet: { get_resource: k8s-subnet} 
            ip_address: {{.MasterIP}}
        {{if $.RouterSecurityGroup }}
         security_groups:
           - {{$.RouterSecurityGroup}}
        {{else}}
         port_security_enabled: false
        {{- end}}

  {{if .ExternalVolumeSize}}
   k8s-master-vol:
      type: OS::Cinder::Volume
      properties:
         name: k8s-master-{{.ClusterName}}-vol
         image: {{.ImageName}}
         size: {{.ExternalVolumeSize}}
  {{- end}}
  {{if .SharedVolumeSize}}
   k8s-shared-vol:
      type: OS::Cinder::Volume
      properties:
         name: k8s-shared-{{.ClusterName}}-vol
         size: {{.SharedVolumeSize}}
  {{- end}}
   k8s-master:
      type: OS::Nova::Server
      properties:
         name: 
            mex-k8s-master-{{.ClusterName}}
      {{if or (.ExternalVolumeSize) (.SharedVolumeSize)}}
         block_device_mapping:
        {{if .ExternalVolumeSize}}
         - device_name: "vda" 
           volume_id: { get_resource: k8s-master-vol }
           delete_on_termination: "false" 
        {{- end}}
        {{if .SharedVolumeSize}}
         - device_name: "vdb" 
           volume_id: { get_resource: k8s-shared-vol }
           delete_on_termination: "false"
        {{- end}}
      {{- end}}
      {{- if not .ExternalVolumeSize}}
         image: {{.ImageName}}
      {{- end}}
         flavor: {{.NodeFlavor}}
         config_drive: true
         user_data_format: RAW
         user_data: |
` + reindent(vmCloudConfig, 12) + `
        {{if .SharedVolumeSize}}
` + reindent(vmCloudConfigShareMount, 12) + `
        {{- end}}
         networks:
          - port: { get_resource: k8s-master-port }
         metadata:
            skipk8s: no
            role: k8s-master 
            edgeproxy: {{.GatewayIP}}
            mex-flavor: {{.NodeFlavor}}
            k8smaster: {{.MasterIP}}

  {{range .Nodes}}
   {{.NodeName}}-port:
      type: OS::Neutron::Port
      properties:
          name: mex-k8s-{{.NodeName}}-port-{{$.ClusterName}}
         {{if $.VnicType}}
          binding:vnic_type: {{$.VnicType}}
         {{- end}}
          network_id: {{$.MEXNetworkName}}
          fixed_ips:
          - subnet: { get_resource: k8s-subnet}
            ip_address: {{.NodeIP}}
         {{if $.RouterSecurityGroup }}
          security_groups:
           - {{$.RouterSecurityGroup}}
         {{else}}
          port_security_enabled: false
         {{- end}}

  {{if $.ExternalVolumeSize}}
   {{.NodeName}}-vol:
      type: OS::Cinder::Volume
      properties:
         name: {{.NodeName}}-vol
         image: {{$.ImageName}}
         size: {{$.ExternalVolumeSize}}
  {{- end }}

   {{.NodeName}}:
      type: OS::Nova::Server
      depends_on: k8s-master
      properties:
         name: {{.NodeName}}-{{$.ClusterName}}
        {{if  $.ExternalVolumeSize}}
         block_device_mapping: [{ device_name: "vda", volume_id: { get_resource: {{.NodeName}}-vol }, delete_on_termination: "false" }]
        {{else}}
         image: {{$.ImageName}}
        {{- end}}
         flavor: {{$.NodeFlavor}}
         config_drive: true
         user_data_format: RAW
         user_data: |
` + reindent(vmCloudConfig, 12) + `
         networks:
          - port: { get_resource: {{.NodeName}}-port } 
         metadata:
            skipk8s: no 
            role: k8s-node
            edgeproxy: {{$.GatewayIP}}
            mex-flavor: {{$.NodeFlavor}}
            k8smaster: {{$.MasterIP}}
  {{end}}
`

func reindent(str string, indent int) string {
	out := ""
	for _, v := range strings.Split(str, "\n") {
		out += strings.Repeat(" ", indent) + v + "\n"
	}
	return strings.TrimSuffix(out, "\n")
}

func WriteTemplateFile(filename string, buf *bytes.Buffer) error {
	outFile, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to write heat template %s: %s", filename, err.Error())
	}
	_, err = outFile.WriteString(buf.String())

	if err != nil {
		outFile.Close()
		os.Remove(filename)
		return fmt.Errorf("unable to write heat template file %s: %s", filename, err.Error())
	}
	outFile.Sync()
	outFile.Close()
	return nil
}

func waitForStack(ctx context.Context, stackname string, action string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "waiting for stack", "name", stackname, "action", action)
	start := time.Now()
	for {
		time.Sleep(10 * time.Second)
		hd, err := getHeatStackDetail(ctx, stackname)
		if action == heatDelete && hd == nil {
			// it's gone
			return nil
		}
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelMexos, "Got Heat Stack detail", "detail", hd)
		updateCallback(edgeproto.UpdateStep, fmt.Sprintf("Heat Stack Status: %s", hd.StackStatus))

		switch hd.StackStatus {
		case action + "_COMPLETE":
			log.SpanLog(ctx, log.DebugLevelMexos, "Heat Stack succeeded", "action", action, "stackName", stackname)
			return nil
		case action + "_IN_PROGRESS":
			elapsed := time.Since(start)
			if elapsed >= (time.Minute * 20) {
				// this should not happen and indicates the stack is stuck somehow
				log.InfoLog("Heat stack taking too long", "status", hd.StackStatus, "elasped time", elapsed)
				return fmt.Errorf("Heat stack taking too long")
			}
			continue
		case action + "_FAILED":
			log.InfoLog("Heat Stack failed", "action", action, "stackName", stackname)
			return fmt.Errorf("Heat Stack failed: %s", hd.StackStatusReason)
		default:
			log.InfoLog("Unexpected Heat Stack status", "status", stackname)
			return fmt.Errorf("Stack create unexpected status: %s", hd.StackStatus)
		}
	}
}

func WithPublicKey(authPublicKey string) VMParamsOp {
	return func(vmp *VMParams) error {
		if authPublicKey == "" {
			return nil
		}
		convKey, err := util.ConvertPEMtoOpenSSH(authPublicKey)
		if err != nil {
			return err
		}
		vmp.AuthPublicKey = convKey
		return nil
	}
}

func WithAccessPorts(accessPorts string) VMParamsOp {
	return func(vmp *VMParams) error {
		var err error
		vmp.AccessPorts, err = util.ParsePorts(accessPorts)
		return err
	}
}

func WithDeploymentManifest(deploymentManifest string) VMParamsOp {
	return func(vmp *VMParams) error {
		vmp.DeploymentManifest = deploymentManifest
		return nil
	}
}

func WithCommand(command string) VMParamsOp {
	return func(vmp *VMParams) error {
		vmp.Command = command
		return nil
	}
}

func GetVMParams(ctx context.Context, depType DeploymentType, serverName, flavorName string, externalVolumeSize uint64, imageName, secGrp string, cloudletKey *edgeproto.CloudletKey, opts ...VMParamsOp) (*VMParams, error) {
	var vmp VMParams
	var err error
	vmp.VMName = serverName
	vmp.FlavorName = flavorName
	vmp.ExternalVolumeSize = externalVolumeSize
	vmp.ImageName = imageName
	vmp.ApplicationSecurityGroup = secGrp
	for _, op := range opts {
		if err := op(&vmp); err != nil {
			return nil, err
		}
	}
	ni, err := ParseNetSpec(ctx, GetCloudletNetworkScheme())
	if err != nil {
		// The netspec should always be present but is not set when running OpenStack from the controller.
		// For now, tolerate this as it will work with default settings but not anywhere that requires a non-default
		// netspec.  TODO This meeds a general fix to allow CreateCloudlet to work with floating IPs.
		log.SpanLog(ctx, log.DebugLevelMexos, "WARNING, empty netspec")
	}
	if depType != UserVMDeployment {
		vmp.IsInternal = true
	}
	if depType == RootLBVMDeployment {
		vmp.GatewayIP, err = GetExternalGateway(ctx, GetCloudletExternalNetwork())
		if err != nil {
			return nil, err
		}
		vmp.MEXRouterIP, err = GetMexRouterIP(ctx)
		if err != nil {
			return nil, err
		}
		vmp.IsRootLB = true
		if cloudletKey == nil {
			return nil, fmt.Errorf("nil cloudlet key")
		}
		cloudletGrp, err := GetCloudletSecurityGroupID(ctx, cloudletKey)
		if err != nil {
			return nil, err
		}
		vmp.CloudletSecurityGroup = cloudletGrp

	}
	if ni != nil && ni.FloatingIPNet != "" {
		fips, err := ListFloatingIPs(ctx)
		for _, f := range fips {
			if f.Port == "" && f.FloatingIPAddress != "" {
				vmp.FloatingIPAddressID = f.ID
			}
		}
		if vmp.FloatingIPAddressID == "" {
			return nil, fmt.Errorf("Unable to allocate a floating IP")
		}
		if err != nil {
			return nil, fmt.Errorf("Unable to list floating IPs %v", err)
		}
		vmp.NetworkName = ni.FloatingIPNet
		vmp.SubnetName = ni.FloatingIPSubnet
	} else {
		vmp.NetworkName = GetCloudletExternalNetwork()
	}
	if ni != nil {
		vmp.VnicType = ni.VnicType
	}
	return &vmp, nil
}

func createOrUpdateHeatStackFromTemplate(ctx context.Context, templateData interface{}, stackName string, templateString string, action string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "createHeatStackFromTemplate", "stackName", stackName)

	var buf bytes.Buffer
	updateCallback(edgeproto.UpdateTask, "Creating Heat Stack for "+stackName)

	funcMap := template.FuncMap{
		"Indent": func(values ...interface{}) string {
			s := values[0].(string)
			l := 4
			if len(values) > 1 {
				l = values[1].(int)
			}
			var newStr []string
			for _, v := range strings.Split(string(s), "\n") {
				nV := fmt.Sprintf("%s%s", strings.Repeat(" ", l), v)
				newStr = append(newStr, nV)
			}
			return strings.Join(newStr, "\n")
		},
	}

	tmpl, err := template.New(stackName).Funcs(funcMap).Parse(templateString)
	if err != nil {
		return fmt.Errorf("template new failed: %s", err)
	}
	err = tmpl.Execute(&buf, templateData)
	if err != nil {
		return fmt.Errorf("Template Execute Failed: %s", err)
	}
	filename := stackName + "-heat.yaml"
	err = WriteTemplateFile(filename, &buf)
	if err != nil {
		return fmt.Errorf("WriteTemplateFile failed: %s", err)
	}
	if action == heatCreate {
		err = createHeatStack(ctx, filename, stackName)
	} else {
		err = updateHeatStack(ctx, filename, stackName)
	}
	if err != nil {
		return err
	}
	err = waitForStack(ctx, stackName, action, updateCallback)
	return err
}

// UpdateHeatStackFromTemplate fills the template from templateData and creates the stack
func UpdateHeatStackFromTemplate(ctx context.Context, templateData interface{}, stackName, templateString string, updateCallback edgeproto.CacheUpdateCallback) error {
	return createOrUpdateHeatStackFromTemplate(ctx, templateData, stackName, templateString, heatUpdate, updateCallback)
}

// CreateHeatStackFromTemplate fills the template from templateData and creates the stack
func CreateHeatStackFromTemplate(ctx context.Context, templateData interface{}, stackName, templateString string, updateCallback edgeproto.CacheUpdateCallback) error {
	return createOrUpdateHeatStackFromTemplate(ctx, templateData, stackName, templateString, heatCreate, updateCallback)
}

// HeatDeleteCluster deletes the stack and also cleans up rootLB port if needed
func HeatDeleteCluster(ctx context.Context, client pc.PlatformClient, clusterInst *edgeproto.ClusterInst, rootLBName string, dedicatedRootLB bool) error {
	cp, err := getClusterParams(ctx, clusterInst, rootLBName, dedicatedRootLB, heatDelete)
	if err == nil {
		// no need to detach the port from the dedicated RootLB because the VM is going away with the stack.  A nil client can be passed here in
		// some rare cases because the server was somehow deleted
		if cp.RootLBPortName != "" && !dedicatedRootLB && client != nil {
			err = DetachAndDisableRootLBInterface(ctx, client, rootLBName, cp.RootLBPortName, cp.GatewayIP)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMexos, "unable to detach rootLB interface, proceed with stack deletion", "err", err)
			}
		}
	} else {
		// probably already gone
		log.SpanLog(ctx, log.DebugLevelMexos, "unable to get cluster params, proceed with stack deletion", "err", err)
	}
	clusterName := k8smgmt.GetK8sNodeNameSuffix(&clusterInst.Key)
	return HeatDeleteStack(ctx, clusterName)
}

// HeatDeleteStack deletes the VM resources
func HeatDeleteStack(ctx context.Context, stackName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "deleting heat stack for stack", "stackName", stackName)
	err := deleteHeatStack(ctx, stackName)
	if err != nil {
		return err
	}
	return waitForStack(ctx, stackName, heatDelete, edgeproto.DummyUpdateCallback)
}

//GetClusterParams fills template parameters for the cluster.  A non blank rootLBName will add a rootlb VM
func getClusterParams(ctx context.Context, clusterInst *edgeproto.ClusterInst, rootLBName string, dedicatedRootLB bool, action string) (*ClusterParams, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "getClusterParams", "cluster", clusterInst, "action", action)

	var cp ClusterParams
	var err error
	ni, err := ParseNetSpec(ctx, GetCloudletNetworkScheme())
	if err != nil {
		return nil, err
	}
	cp.NetworkType = ni.NetworkType

	cp.VnicType = ni.VnicType
	// dedicated rootLB requires a rootLB VM to be created in the stack
	if dedicatedRootLB {
		cp.VMParams, err = GetVMParams(ctx,
			RootLBVMDeployment,
			rootLBName,
			clusterInst.NodeFlavor,
			clusterInst.ExternalVolumeSize,
			GetCloudletOSImage(),
			GetSecurityGroupName(ctx, rootLBName),
			&clusterInst.Key.CloudletKey,
		)
		if err != nil {
			return nil, fmt.Errorf("Unable to get rootlb params: %v", err)
		}
	} else {
		// we still use the security group from the VM params even for shared
		cp.VMParams = &VMParams{}
	}
	cloudletGrp, err := GetCloudletSecurityGroupID(ctx, &clusterInst.Key.CloudletKey)
	if err != nil {
		return nil, err
	}
	cp.CloudletSecurityGroup = cloudletGrp
	cp.ClusterName = k8smgmt.GetK8sNodeNameSuffix(&clusterInst.Key)
	rtr := GetCloudletExternalRouter()
	if rtr == NoConfigExternalRouter {
		log.SpanLog(ctx, log.DebugLevelMexos, "NoConfigExternalRouter in use for cluster, cluster stack with no router interfaces")
	} else if rtr == NoExternalRouter {
		log.SpanLog(ctx, log.DebugLevelMexos, "NoExternalRouter in use for cluster, cluster stack with rootlb connected to subnet")
		cp.RootLBConnectToSubnet = rootLBName
		cp.RootLBPortName = fmt.Sprintf("%s-%s-port", rootLBName, cp.ClusterName)
	} else {
		log.SpanLog(ctx, log.DebugLevelMexos, "External router in use for cluster, cluster stack with router interfaces")
		cp.MEXRouterName = rtr
		// The cluster needs to be connected to the cloudlet level security group to have router access
		cp.RouterSecurityGroup = cloudletGrp
	}
	cp.MEXNetworkName = GetCloudletMexNetwork()
	cp.ImageName = GetCloudletOSImage()
	cp.ApplicationSecurityGroup = GetSecurityGroupName(ctx, rootLBName)
	usedCidrs := make(map[string]string)

	currentSubnetName := ""
	found := false
	if action != heatCreate {
		currentSubnetName = "mex-k8s-subnet-" + cp.ClusterName
	}
	sns, snserr := ListSubnets(ctx, ni.Name)
	if snserr != nil {
		return nil, fmt.Errorf("can't get list of subnets for %s, %v", ni.Name, snserr)
	}
	for _, s := range sns {
		usedCidrs[s.Subnet] = s.Name
	}

	nodeIPPrefix := ""

	//find an available subnet or the current subnet for update and delete
	for i := 0; i <= 255; i++ {
		subnet := fmt.Sprintf("%s.%s.%d.%d/%s", ni.Octets[0], ni.Octets[1], i, 0, ni.NetmaskBits)
		// either look for an unused one (create) or the current one (update)
		if (action == heatCreate && usedCidrs[subnet] == "") || (action != heatCreate && usedCidrs[subnet] == currentSubnetName) {
			found = true
			cp.CIDR = subnet
			cp.GatewayIP = fmt.Sprintf("%s.%s.%d.%d", ni.Octets[0], ni.Octets[1], i, 1)
			cp.MasterIP = fmt.Sprintf("%s.%s.%d.%d", ni.Octets[0], ni.Octets[1], i, 10)
			nodeIPPrefix = fmt.Sprintf("%s.%s.%d", ni.Octets[0], ni.Octets[1], i)
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("cannot find subnet cidr")
	}

	if clusterInst.NodeFlavor == "" {
		return nil, fmt.Errorf("Node Flavor is not set")
	}
	cp.NodeFlavor = clusterInst.NodeFlavor
	cp.ExternalVolumeSize = clusterInst.ExternalVolumeSize
	cp.SharedVolumeSize = clusterInst.SharedVolumeSize
	for i := uint32(1); i <= clusterInst.NumNodes; i++ {
		nn := HeatNodePrefix(i)
		nip := fmt.Sprintf("%s.%d", nodeIPPrefix, i+100)
		cn := ClusterNode{NodeName: nn, NodeIP: nip}
		cp.Nodes = append(cp.Nodes, cn)
	}
	// cloudflare primary and backup
	cp.DNSServers = []string{"1.1.1.1", "1.0.0.1"}
	return &cp, nil
}

func HeatNodePrefix(num uint32) string {
	return fmt.Sprintf("%s%d", cloudcommon.MexNodePrefix, num)
}

func ParseHeatNodePrefix(name string) (bool, uint32) {
	reg := regexp.MustCompile("^" + cloudcommon.MexNodePrefix + "(\\d+).*")
	matches := reg.FindSubmatch([]byte(name))
	if matches == nil || len(matches) < 2 {
		return false, 0
	}
	num, _ := strconv.Atoi(string(matches[1]))
	return true, uint32(num)
}

// HeatCreateRootLBVM creates a roobLB VM
func HeatCreateRootLBVM(ctx context.Context, serverName string, stackName string, vmspec *vmspec.VMCreationSpec, cloudletKey *edgeproto.CloudletKey, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "HeatCreateRootLBVM", "serverName", serverName, "stackName", stackName, "vmspec", vmspec)
	ni, err := ParseNetSpec(ctx, GetCloudletNetworkScheme())
	if err != nil {
		return err
	}
	// lock here to avoid getting the same floating IP; we need to lock until the stack is done
	// Floating IPs are allocated both by VM and cluster creation
	// TODO: floating IP lock should apply to developer app VMs also
	if ni.FloatingIPNet != "" {
		heatStackLock.Lock()
		defer heatStackLock.Unlock()
	}
	vmp, err := GetVMParams(ctx,
		RootLBVMDeployment,
		serverName,
		vmspec.FlavorName,
		vmspec.ExternalVolumeSize,
		GetCloudletOSImage(),
		GetSecurityGroupName(ctx, serverName),
		cloudletKey,
	)
	if err != nil {
		return fmt.Errorf("Unable to get VM params: %v", err)
	}
	return CreateHeatStackFromTemplate(ctx, vmp, stackName, VmTemplate, updateCallback)
}

// HeatCreateClusterKubernetes creates a k8s cluster which may optionally include a dedicated root LB
func HeatCreateClusterKubernetes(ctx context.Context, clusterInst *edgeproto.ClusterInst, rootLBName string, dedicatedRootLB bool, updateCallback edgeproto.CacheUpdateCallback) error {

	log.SpanLog(ctx, log.DebugLevelMexos, "HeatCreateClusterKubernetes", "clusterInst", clusterInst, "rootLBName", rootLBName)
	// It is problematic to create 2 clusters at the exact same time because we will look for available subnet CIDRS when
	// defining the template.  If 2 start at once they may end up trying to create the same subnet and one will fail.
	// So we will do this one at a time.   It will slightly slow down the creation of the second cluster, but the heat
	// stack create time is relatively quick compared to the k8s startup which can be done in parallel
	// Floating IPs can also be allocated within the stack and need to be locked as well.
	heatStackLock.Lock()
	defer heatStackLock.Unlock()

	cp, err := getClusterParams(ctx, clusterInst, rootLBName, dedicatedRootLB, heatCreate)
	if err != nil {
		return err
	}

	templateString := k8sClusterTemplate
	//append the VM resources for the rootLB is dedicated
	if dedicatedRootLB {
		templateString += vmTemplateResources
	}
	err = CreateHeatStackFromTemplate(ctx, cp, cp.ClusterName, templateString, updateCallback)
	if err != nil {
		return err
	}
	if cp.RootLBPortName != "" {
		client, err := GetSSHClient(ctx, rootLBName, GetCloudletExternalNetwork(), SSHUser)
		if err != nil {
			return fmt.Errorf("unable to get rootlb SSH client: %v", err)
		}
		return AttachAndEnableRootLBInterface(ctx, client, rootLBName, cp.RootLBPortName, cp.GatewayIP)
	}
	return nil
}

// HeatUpdateClusterKubernetes updates a k8s cluster which may optionally include a dedicated root LB
func HeatUpdateClusterKubernetes(ctx context.Context, clusterInst *edgeproto.ClusterInst, rootLBName string, dedicatedRootLB bool, updateCallback edgeproto.CacheUpdateCallback) error {

	log.SpanLog(ctx, log.DebugLevelMexos, "HeatUpdateClusterKubernetes", "clusterInst", clusterInst, "rootLBName", rootLBName, "dedicatedRootLB", dedicatedRootLB)

	cp, err := getClusterParams(ctx, clusterInst, rootLBName, dedicatedRootLB, heatUpdate)
	if err != nil {
		return err
	}

	templateString := k8sClusterTemplate
	//append the VM resources for the rootLB is specified
	if dedicatedRootLB {
		templateString += vmTemplateResources
	}
	err = UpdateHeatStackFromTemplate(ctx, cp, cp.ClusterName, templateString, updateCallback)
	if err != nil {
		return err
	}
	// It it is possible this cluster was created before the default was to use a router
	if cp.RootLBPortName != "" {
		client, err := GetSSHClient(ctx, rootLBName, GetCloudletExternalNetwork(), SSHUser)
		if err != nil {
			return fmt.Errorf("unable to get rootlb SSH client: %v", err)
		}
		return AttachAndEnableRootLBInterface(ctx, client, rootLBName, cp.RootLBPortName, cp.GatewayIP)
	}
	return nil
}
