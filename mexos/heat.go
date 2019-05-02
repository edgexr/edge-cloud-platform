package mexos

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
)

type VMParams struct {
	VMName              string
	Flavor              string
	ImageName           string
	SecurityGroup       string
	NetworkName         string
	SubnetName          string
	MEXRouterIP         string
	GatewayIP           string
	FloatingIPAddressID string
	AuthPublicKey       template.HTML // Must be of this type to skip HTML escaping
	AccessPorts         []util.PortSpec
	DeploymentManifest  template.HTML
	Command             template.HTML
	IsRootLB            bool
}

type DeploymentType string

const (
	RootLBVMDeployment DeploymentType = "mexrootlb"
	UserVMDeployment   DeploymentType = "mexuservm"
)

var heatStackLock sync.Mutex

// This is the resources part of a template for a VM. It is for use within another template
// the parameters under VMP can come from either a standalone struture (VM Create) or a cluster (for rootLB)
var vmTemplateResources = `
   {{.VMName}}:
      type: OS::Nova::Server
      properties:
         name: 
            {{.VMName}}
         image: {{.ImageName}}
        {{if not .FloatingIPAddressID}}
         security_groups:
          - {{.SecurityGroup}}
         {{if .AccessPorts}} - { get_resource: vm_security_group } {{- end}}
        {{- end}}
         flavor: {{.Flavor}}
        {{if .AuthPublicKey}} key_name: { get_resource: ssh_key_pair } {{- end}}
         config_drive: true       
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
            mex-flavor: {{.Flavor}}
            privaterouter: {{.MEXRouterIP}}
         user_data_format: RAW
         user_data: 
            get_file: /root/.mobiledgex/userdata.txt 
        {{- end}}
        {{if .DeploymentManifest}}
         user_data_format: RAW
         user_data: |
{{ Indent .DeploymentManifest 13 }}
        {{- end}}
        {{if .Command}}
         user_data_format: RAW
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
           network_id: {{.NetworkName}}
           fixed_ips: 
            - subnet_id: {{.SubnetName}}
           security_groups:
            - {{$.SecurityGroup}}
           {{if .AccessPorts}} - { get_resource: vm_security_group } {{- end}}
   floatingip:
       type: OS::Neutron::FloatingIPAssociation
       properties:
          floatingip_id: {{.FloatingIPAddressID}}
          port_id: { get_resource: vm-port }
  {{- end}}
  {{if .AccessPorts}}
   vm_security_group:
       type: OS::Neutron::SecurityGroup
       properties:
          name: {{.VMName}}-sg
          rules: [
             {{range .AccessPorts}}
              {remote_ip_prefix: 0.0.0.0/0,
               protocol: {{.Proto}},
               port_range_min: {{.Port}},
               port_range_max: {{.Port}}},
             {{end}}
          ]
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
	MasterFlavor   string
	NodeFlavor     string
	ImageName      string
	SecurityGroup  string
	MEXRouterName  string
	MEXNetworkName string
	ClusterName    string
	CIDR           string
	GatewayIP      string
	MasterIP       string
	Nodes          []ClusterNode
	*VMParams      //rootlb
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
        name: 
           mex-k8s-subnet-{{.ClusterName}}

   router-port:
       type: OS::Neutron::Port
       properties:
          name: mex-k8s-subnet-{{.ClusterName}}
          network_id: mex-k8s-net-1
          fixed_ips:
          - subnet: { get_resource: k8s-subnet}
            ip_address: {{.GatewayIP}}
          security_groups:
           - {{$.SecurityGroup}}

   router-interface:
      type: OS::Neutron::RouterInterface
      properties:
         router:  {{.MEXRouterName}}
         port: { get_resource: router-port }

   k8s-master-port:
      type: OS::Neutron::Port
      properties:
         name: k8s-master-port
         network_id: {{.MEXNetworkName}}
         fixed_ips:
          - subnet: { get_resource: k8s-subnet} 
            ip_address: {{.MasterIP}}
         security_groups:
          - {{$.SecurityGroup}}

   k8s_master:
      type: OS::Nova::Server
      properties:
         name: 
            mex-k8s-master-{{.ClusterName}}
         image: {{.ImageName}}
         flavor: {{.MasterFlavor}}
         config_drive: true
         user_data_format: RAW
         user_data:
            get_file: /root/.mobiledgex/userdata.txt
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
          name: mex-k8s-master-port-{{$.ClusterName}}
          network_id: {{$.MEXNetworkName}}
          fixed_ips:
          - subnet: { get_resource: k8s-subnet}
            ip_address: {{.NodeIP}}
          security_groups:
           - {{$.SecurityGroup}}

   {{.NodeName}}:
      type: OS::Nova::Server
      depends_on: k8s_master
      properties:
         name: {{.NodeName}}-{{$.ClusterName}}
         image: {{$.ImageName}}
         flavor: {{$.NodeFlavor}}
         config_drive: true
         user_data_format: RAW
         user_data:
            get_file: /root/.mobiledgex/userdata.txt
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

func writeTemplateFile(filename string, buf *bytes.Buffer) error {
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

func waitForStackCreate(stackname string) error {
	start := time.Now()
	for {
		time.Sleep(10 * time.Second)
		hd, err := getHeatStackDetail(stackname)
		if err != nil {
			return err
		}
		log.DebugLog(log.DebugLevelMexos, "Got Heat Stack detail", "detail", hd)
		switch hd.StackStatus {
		case "CREATE_COMPLETE":
			log.DebugLog(log.DebugLevelMexos, "Heat Stack Creation succeeded", "stackName", stackname)
			return nil
		case "CREATE_IN_PROGRESS":
			elapsed := time.Since(start)
			if elapsed >= (time.Minute * 20) {
				// this should not happen and indicates the stack is stuck somehow
				log.InfoLog("Heat stack create taking too long", "status", hd.StackStatus, "elasped time", elapsed)
				return fmt.Errorf("Heat stack create taking too long")
			}
			continue
		case "CREATE_FAILED":
			log.InfoLog("Heat Stack Creation failed", "stackName", stackname)
			return fmt.Errorf("Heat Stack create failed")
		default:
			log.InfoLog("Unexpected Heat Stack status", "status", stackname)
			return fmt.Errorf("Stack create unexpected status: %s", hd.StackStatus)
		}
	}
}

func waitForStackDelete(stackname string) error {
	for {
		time.Sleep(5 * time.Second)
		hd, _ := getHeatStackDetail(stackname)
		if hd == nil {
			// it's gone
			return nil
		}
		log.DebugLog(log.DebugLevelMexos, "Got Heat Stack detail", "detail", hd)
		switch hd.StackStatus {
		case "DELETE_IN_PROGRESS":
			continue
		case "DELETE_FAILED":
			log.InfoLog("Heat Stack Deletion failed", "stackName", stackname)
			return fmt.Errorf("Heat Stack delete failed")
		case "DELETE_COMPLETE":
			return nil
		default:
			log.InfoLog("Unexpected Heat Stack status", "status", hd.StackStatus)
			return fmt.Errorf("Stack delete unexpected status: %s", hd.StackStatus)
		}
	}
}

func GetVMParams(depType DeploymentType, serverName, flavor, imageName, authPublicKey, accessPorts, deploymentManifest, command string, ni *NetSpecInfo) (*VMParams, error) {
	var vmp VMParams
	var err error
	vmp.VMName = serverName
	vmp.Flavor = flavor
	vmp.ImageName = imageName
	vmp.SecurityGroup = GetCloudletSecurityGroup()
	if depType == RootLBVMDeployment {
		vmp.GatewayIP, err = GetExternalGateway(GetCloudletExternalNetwork())
		if err != nil {
			return nil, err
		}
		vmp.MEXRouterIP, err = GetMexRouterIP()
		if err != nil {
			return nil, err
		}
		vmp.IsRootLB = true
	}
	if authPublicKey != "" {
		convKey, err := util.ConvertPEMtoOpenSSH(authPublicKey)
		if err != nil {
			return nil, err
		}
		vmp.AuthPublicKey = template.HTML(convKey)
	}
	if accessPorts != "" {
		vmp.AccessPorts, err = util.ParsePorts(accessPorts)
		if err != nil {
			return nil, err
		}
	}
	if deploymentManifest != "" {
		vmp.DeploymentManifest = template.HTML(deploymentManifest)
	}
	if command != "" {
		vmp.Command = template.HTML(command)
	}
	if ni != nil && ni.FloatingIPNet != "" {

		fips, err := ListFloatingIPs()
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
	return &vmp, nil
}

// createHeatStackFromTemplate fills the template from templateData and creates the stack
func CreateHeatStackFromTemplate(templateData interface{}, stackName, templateString string) error {
	log.DebugLog(log.DebugLevelMexos, "createHeatStackFromTemplate", "stackName", stackName)

	var buf bytes.Buffer

	funcMap := template.FuncMap{
		"Indent": func(values ...interface{}) template.HTML {
			s := values[0].(template.HTML)
			l := 4
			if len(values) > 1 {
				l = values[1].(int)
			}
			var newStr []string
			for _, v := range strings.Split(string(s), "\n") {
				nV := fmt.Sprintf("%s%s", strings.Repeat(" ", l), v)
				newStr = append(newStr, nV)
			}
			return template.HTML(strings.Join(newStr, "\n"))
		},
	}

	tmpl, err := template.New(stackName).Funcs(funcMap).Parse(templateString)
	if err != nil {
		return err
	}
	err = tmpl.Execute(&buf, templateData)
	if err != nil {
		return err
	}
	filename := stackName + "-heat.yaml"
	err = writeTemplateFile(filename, &buf)
	if err != nil {
		return err
	}
	err = createHeatStack(filename, stackName)
	if err != nil {
		return err
	}
	err = waitForStackCreate(stackName)
	return err
}

// HeatDeleteVM deletes the VM resources
func HeatDeleteStack(stackName string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting heat stack for stack", "stackName", stackName)
	deleteHeatStack(stackName)
	return waitForStackDelete(stackName)
}

//GetClusterParams fills template parameters for the cluster.  A non blank rootLBName will add a rootlb VM
func getClusterParams(clusterInst *edgeproto.ClusterInst, flavor *edgeproto.ClusterFlavor, rootLBName string) (*ClusterParams, error) {
	var cp ClusterParams
	var err error
	ni, err := ParseNetSpec(GetCloudletNetworkScheme())
	if err != nil {
		return nil, err
	}
	if rootLBName != "" {
		cp.VMParams, err = GetVMParams(
			RootLBVMDeployment,
			rootLBName,
			clusterInst.NodeFlavor,
			GetCloudletOSImage(),
			"", // AuthPublicKey
			"", // AccessPorts
			"", // DeploymentManifest
			"", // Command
			ni,
		)
		if err != nil {
			return nil, fmt.Errorf("Unable to get rootlb params: %v", err)
		}
	}
	usedCidrs := make(map[string]bool)

	sns, snserr := ListSubnets(ni.Name)
	if snserr != nil {
		return nil, fmt.Errorf("can't get list of subnets for %s, %v", ni.Name, snserr)
	}
	for _, s := range sns {
		usedCidrs[s.Subnet] = true
	}

	found := false
	nodeIPPrefix := ""

	//find an available subnet
	for i := 0; i <= 255; i++ {
		subnet := fmt.Sprintf("%s.%s.%d.%d/%s", ni.Octets[0], ni.Octets[1], i, 0, ni.NetmaskBits)
		if !usedCidrs[subnet] {
			found = true
			cp.CIDR = subnet
			cp.GatewayIP = fmt.Sprintf("%s.%s.%d.%d", ni.Octets[0], ni.Octets[1], i, 1)
			cp.MasterIP = fmt.Sprintf("%s.%s.%d.%d", ni.Octets[0], ni.Octets[1], i, 2)
			nodeIPPrefix = fmt.Sprintf("%s.%s.%d", ni.Octets[0], ni.Octets[1], i)
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("cannot find free subnet cidr")
	}

	cp.ClusterName = k8smgmt.GetK8sNodeNameSuffix(clusterInst)
	cp.MEXRouterName = GetCloudletExternalRouter()
	cp.MEXNetworkName = GetCloudletMexNetwork()
	cp.ImageName = GetCloudletOSImage()
	cp.SecurityGroup = GetCloudletSecurityGroup()

	if clusterInst.MasterFlavor == "" {
		return nil, fmt.Errorf("Master Flavor is not set")
	}
	if clusterInst.NodeFlavor == "" {
		return nil, fmt.Errorf("Node Flavor is not set")
	}
	cp.MasterFlavor = clusterInst.MasterFlavor
	cp.NodeFlavor = clusterInst.NodeFlavor
	for i := uint32(1); i <= flavor.NumNodes; i++ {
		nn := fmt.Sprintf("mex-k8s-node-%d", i)
		nip := fmt.Sprintf("%s.%d", nodeIPPrefix, i+100)
		cn := ClusterNode{NodeName: nn, NodeIP: nip}
		cp.Nodes = append(cp.Nodes, cn)
	}
	return &cp, nil
}

// HeatCreateRootLBVM creates a roobLB VM
func HeatCreateRootLBVM(serverName string, stackName string, flavor string) error {
	log.DebugLog(log.DebugLevelMexos, "HeatCreateRootLBVM", "serverName", serverName, "stackName", stackName, "flavor", flavor)
	ni, err := ParseNetSpec(GetCloudletNetworkScheme())
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
	vmp, err := GetVMParams(
		RootLBVMDeployment,
		serverName,
		flavor,
		GetCloudletOSImage(),
		"", // AuthPublicKey
		"", // AccessPorts
		"", // DeploymentManifest
		"", // Command
		ni,
	)
	if err != nil {
		return fmt.Errorf("Unable to get VM params: %v", err)
	}
	return CreateHeatStackFromTemplate(vmp, stackName, VmTemplate)
}

// HeatCreateClusterKubernetes creates a k8s cluster which may optionally include a dedicated root LB
func HeatCreateClusterKubernetes(clusterInst *edgeproto.ClusterInst, flavor *edgeproto.ClusterFlavor, dedicatedRootLBName string) error {

	log.DebugLog(log.DebugLevelMexos, "HeatCreateClusterKubernetes", "clusterInst", clusterInst)
	// It is problematic to create 2 clusters at the exact same time because we will look for available subnet CIDRS when
	// defining the template.  If 2 start at once they may end up trying to create the same subnet and one will fail.
	// So we will do this one at a time.   It will slightly slow down the creation of the second cluster, but the heat
	// stack create time is relatively quick compared to the k8s startup which can be done in parallel
	// Floating IPs can also be allocated within the stack and need to be locked as well.
	heatStackLock.Lock()
	defer heatStackLock.Unlock()

	cp, err := getClusterParams(clusterInst, flavor, dedicatedRootLBName)
	if err != nil {
		return err
	}

	templateString := k8sClusterTemplate
	//append the VM resources for the rootLB is specified
	if dedicatedRootLBName != "" {
		templateString += vmTemplateResources
	}
	err = CreateHeatStackFromTemplate(cp, cp.ClusterName, templateString)
	return err
}
