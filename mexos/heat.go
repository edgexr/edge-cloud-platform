package mexos

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"sync"
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

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
	MEXRouterName  string
	MEXNetworkName string
	ClusterName    string
	CIDR           string
	GatewayIP      string
	MasterIP       string
	Nodes          []ClusterNode
}

var clusterCreateLock sync.Mutex

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

//GetClusterParams fills template parameters for the cluster
func getClusterParams(clusterInst *edgeproto.ClusterInst) (*ClusterParams, error) {
	ni, err := ParseNetSpec(GetCloudletNetworkScheme())
	if err != nil {
		return nil, err
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
	var cp ClusterParams
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

	cp.ClusterName = GetK8sNodeNameSuffix(clusterInst)
	cp.MEXRouterName = GetCloudletExternalRouter()
	cp.MEXNetworkName = GetCloudletMexNetwork()
	cp.ImageName = GetCloudletOSImage()
	flavorName := clusterInst.Flavor.Name

	cf, err := GetClusterFlavor(flavorName)
	if err != nil {
		return nil, err
	}
	cp.MasterFlavor = cf.MasterFlavor.Name
	cp.NodeFlavor = cf.NodeFlavor.Name
	for i := 1; i <= cf.NumNodes; i++ {
		nn := fmt.Sprintf("mex-k8s-node-%d", i)
		nip := fmt.Sprintf("%s.%d", nodeIPPrefix, i+100)
		cn := ClusterNode{NodeName: nn, NodeIP: nip}
		cp.Nodes = append(cp.Nodes, cn)
	}
	return &cp, nil
}

func heatCreateClusterKubernetes(clusterInst *edgeproto.ClusterInst) error {

	// It is problematic to create 2 clusters at the exact same time because we will look for available subnet CIDRS when
	// defining the template.  If 2 start at once they may end up trying to create the same subnet and one will fail.
	// So we will do this one at a time.   It will slightly slow down the creation of the second cluster, but the heat
	// stack create time is relatively quick compared to the k8s startup which can be done in parallel
	clusterCreateLock.Lock()
	defer clusterCreateLock.Unlock()

	cp, err := getClusterParams(clusterInst)
	if err != nil {
		return err
	}

	tmpl, err := template.New("mexk8s").Parse(k8sClusterTemplate)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, cp)
	if err != nil {
		return err
	}
	filename := cp.ClusterName + "-heat.yaml"
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

	err = createHeatStack(filename, cp.ClusterName)
	if err != nil {
		return err
	}
	start := time.Now()
	for {
		time.Sleep(10 * time.Second)
		hd, err := getHeatStackDetail(cp.ClusterName)
		if err != nil {
			return err
		}
		log.DebugLog(log.DebugLevelMexos, "Got Heat Stack detail", "detail", hd)
		switch hd.StackStatus {
		case "CREATE_COMPLETE":
			log.DebugLog(log.DebugLevelMexos, "Heat Stack Creation succeeded", "stackName", cp.ClusterName)
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
			log.InfoLog("Heat Stack Creation failed", "stackName", cp.ClusterName)
			return fmt.Errorf("Heat Stack create for cluster failed")
		default:
			log.InfoLog("Unexpected Heat Stack status", "status", hd.StackStatus)
			return fmt.Errorf("Stack create for cluster unexpected status: %s", hd.StackStatus)
		}

	}

}

// HeatDeleteClusterKubernetes deletes the cluster resources
func heatDeleteClusterKubernetes(clusterInst *edgeproto.ClusterInst) error {

	clusterName := GetK8sNodeNameSuffix(clusterInst)
	log.DebugLog(log.DebugLevelMexos, "deleting heat stack for cluster", "stackName", clusterName)
	deleteHeatStack(clusterName)
	for {
		time.Sleep(5 * time.Second)
		hd, _ := getHeatStackDetail(clusterName)
		if hd == nil {
			// it's gone
			return nil
		}
		log.DebugLog(log.DebugLevelMexos, "Got Heat Stack detail", "detail", hd)
		switch hd.StackStatus {
		case "DELETE_IN_PROGRESS":
			continue
		case "DELETE_FAILED":
			log.InfoLog("Heat Stack Deletion failed", "stackName", clusterName)
			return fmt.Errorf("Heat Stack delete for cluster failed")
		case "DELETE_COMPLETE":
			return nil
		default:
			log.InfoLog("Unexpected Heat Stack status", "status", hd.StackStatus)
			return fmt.Errorf("Stack delete for cluster unexpected status: %s", hd.StackStatus)
		}
	}
}
