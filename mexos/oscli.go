package mexos

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func TimedOpenStackCommand(name string, a ...string) ([]byte, error) {
	parmstr := ""
	start := time.Now()

	for _, a := range a {
		parmstr += a + " "
	}
	log.DebugLog(log.DebugLevelMexos, "OpenStack Command Start", "name", name, "parms", parmstr)
	out, err := sh.Command(name, a).CombinedOutput()
	if err != nil {
		log.InfoLog("Openstack command returned error", "parms", parmstr, "err", err, "out", string(out), "elapsed time", time.Since(start))
		return nil, err
	}
	log.DebugLog(log.DebugLevelMexos, "OpenStack Command Done", "parmstr", parmstr, "elapsed time", time.Since(start))
	return out, nil

}

//ListServers returns list of servers, KVM instances, running on the system
func ListServers() ([]OSServer, error) {
	out, err := TimedOpenStackCommand("openstack", "server", "list", "-f", "json")

	if err != nil {
		err = fmt.Errorf("cannot get server list, %v", err)
		return nil, err
	}
	var servers []OSServer
	err = json.Unmarshal(out, &servers)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return servers, nil
}

//ListImages lists avilable images in glance
func ListImages() ([]OSImage, error) {
	out, err := TimedOpenStackCommand("openstack", "image", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get image list, %v", err)
		return nil, err
	}
	var images []OSImage
	err = json.Unmarshal(out, &images)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.DebugLog(log.DebugLevelMexos, "list images", "images", images)
	return images, nil
}

//ListNetworks lists networks known to the platform. Some created by the operator, some by users.
func ListNetworks() ([]OSNetwork, error) {
	out, err := TimedOpenStackCommand("openstack", "network", "list", "-f", "json")
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "network list failed", "out", out)
		err = fmt.Errorf("cannot get network list, %v", err)
		return nil, err
	}
	var networks []OSNetwork
	err = json.Unmarshal(out, &networks)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.DebugLog(log.DebugLevelMexos, "list networks", "networks", networks)
	return networks, nil
}

//ListFlavors lists flavors known to the platform. These vary. On Buckhorn cloudlet the are m4. prefixed.
func ListFlavors() ([]OSFlavor, error) {
	out, err := TimedOpenStackCommand("openstack", "flavor", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get flavor list, %v", err)
		return nil, err
	}
	var flavors []OSFlavor
	err = json.Unmarshal(out, &flavors)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return flavors, nil
}

func ListFloatingIPs() ([]OSFloatingIP, error) {
	out, err := TimedOpenStackCommand("openstack", "floating", "ip", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get floating ip list, %v", err)
		return nil, err
	}
	var fips []OSFloatingIP
	err = json.Unmarshal(out, &fips)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return fips, nil
}

//CreateServer instantiates a new server instance, which is a KVM instance based on a qcow2 image from glance
func CreateServer(opts *OSServerOpt) error {
	args := []string{
		"server", "create",
		"--config-drive", "true", //XXX always
		"--image", opts.Image, "--flavor", opts.Flavor,
	}
	if opts.UserData != "" {
		args = append(args, "--user-data", opts.UserData)
	}
	for _, p := range opts.Properties {
		args = append(args, "--property", p)
		// `p` should be like: "key=value"
	}
	for _, n := range opts.NetIDs {
		args = append(args, "--nic", "net-id="+n)
		// `n` should be like: "public,v4-fixed-ip=172.24.4.201"
	}
	args = append(args, opts.Name)
	//TODO additional args
	iargs := make([]string, len(args))
	for i, v := range args {
		iargs[i] = v
	}
	log.DebugLog(log.DebugLevelMexos, "creating server with args", "iargs", iargs)

	//log.DebugLog(log.DebugLevelMexos, "openstack create server", "opts", opts, "iargs", iargs)
	out, err := TimedOpenStackCommand("openstack", iargs...)
	if err != nil {
		err = fmt.Errorf("cannot create server, %v, '%s'", err, out)
		return err
	}
	return nil
}

// GetServerDetails returns details of the KVM instance
func GetServerDetails(name string) (*OSServerDetail, error) {
	active := false
	srvDetail := &OSServerDetail{}
	for i := 0; i < 10; i++ {
		out, err := TimedOpenStackCommand("openstack", "server", "show", "-f", "json", name)
		if err != nil {
			err = fmt.Errorf("can't show server %s, %s, %v", name, out, err)
			return nil, err
		}
		//fmt.Printf("%s\n", out)
		err = json.Unmarshal(out, srvDetail)
		if err != nil {
			err = fmt.Errorf("cannot unmarshal while getting server detail, %v", err)
			return nil, err
		}
		if srvDetail.Status == "ACTIVE" {
			active = true
			break
		}
		log.DebugLog(log.DebugLevelMexos, "wait for server to become ACTIVE", "server detail", srvDetail)
		time.Sleep(30 * time.Second)
	}
	if !active {
		return nil, fmt.Errorf("while getting server detail, waited but server %s is too slow getting to active state", name)
	}
	//log.DebugLog(log.DebugLevelMexos, "server detail", "server detail", srvDetail)
	return srvDetail, nil
}

//DeleteServer destroys a KVM instance
//  sometimes it is not possible to destroy. Like most things in Openstack, try again.
func DeleteServer(id string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting server", "id", id)
	out, err := TimedOpenStackCommand("openstack", "server", "delete", id)
	if err != nil {
		err = fmt.Errorf("can't delete server %s, %s, %v", id, out, err)
		return err
	}
	return nil
}

// CreateNetwork creates a network with a name.
func CreateNetwork(name string) error {
	log.DebugLog(log.DebugLevelMexos, "creating network", "network", name)
	out, err := TimedOpenStackCommand("openstack", "network", "create", name)
	if err != nil {
		err = fmt.Errorf("can't create network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//DeleteNetwork destroys a named network
//  Sometimes it will fail. Openstack will refuse if there are resources attached.
func DeleteNetwork(name string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting network", "network", name)
	out, err := TimedOpenStackCommand("openstack", "network", "delete", name)
	if err != nil {
		err = fmt.Errorf("can't delete network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//CreateSubnet creates a subnet within a network. A subnet is assigned ranges. Optionally DHCP can be enabled.
func CreateSubnet(netRange, networkName, gatewayAddr, subnetName string, dhcpEnable bool) error {
	var dhcpFlag string
	if dhcpEnable {
		dhcpFlag = "--dhcp"
	} else {
		dhcpFlag = "--no-dhcp"
	}
	out, err := TimedOpenStackCommand("openstack", "subnet", "create",
		"--subnet-range", netRange, // e.g. 10.101.101.0/24
		"--network", networkName, // mex-k8s-net-1
		dhcpFlag,
		"--gateway", gatewayAddr, // e.g. 10.101.101.1
		subnetName) // e.g. mex-k8s-subnet-1
	if err != nil {
		nerr := &NeutronErrorType{}
		if ix := strings.Index(string(out), `{"NeutronError":`); ix > 0 {
			neutronErr := out[ix:]
			if jerr := json.Unmarshal(neutronErr, nerr); jerr != nil {
				err = fmt.Errorf("can't create subnet %s, %s, %v, error while parsing neutron error, %v", subnetName, out, err, jerr)
				return err
			}
			if strings.Index(nerr.NeutronError.Message, "overlap") > 0 {
				sd, serr := GetSubnetDetail(subnetName)
				if serr != nil {
					return fmt.Errorf("cannot get subnet detail for %s, while fixing overlap error, %v", subnetName, serr)
				}
				log.DebugLog(log.DebugLevelMexos, "create subnet, existing subnet detail", "subnet detail", sd)

				//XXX do more validation

				log.DebugLog(log.DebugLevelMexos, "create subnet, reusing existing subnet", "result", out, "error", err)
				return nil
			}
		}
		err = fmt.Errorf("can't create subnet %s, %s, %v", subnetName, out, err)
		return err
	}
	return nil
}

//DeleteSubnet deletes the subnet. If this fails, remove any attached resources, like router, and try again.
func DeleteSubnet(subnetName string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting subnet", "name", subnetName)
	out, err := TimedOpenStackCommand("openstack", "subnet", "delete", subnetName)
	if err != nil {
		err = fmt.Errorf("can't delete subnet %s, %s, %v", subnetName, out, err)
		return err
	}
	return nil
}

//CreateRouter creates new router. A router can be attached to network and subnets.
func CreateRouter(routerName string) error {
	log.DebugLog(log.DebugLevelMexos, "creating router", "name", routerName)
	out, err := TimedOpenStackCommand("openstack", "router", "create", routerName)
	if err != nil {
		err = fmt.Errorf("can't create router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//DeleteRouter removes the named router. The router needs to not be in use at the time of deletion.
func DeleteRouter(routerName string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting router", "name", routerName)
	out, err := TimedOpenStackCommand("openstack", "router", "delete", routerName)
	if err != nil {
		err = fmt.Errorf("can't delete router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//SetRouter assigns the router to a particular network. The network needs to be attached to
// a real external network. This is intended only for routing to external network for now. No internal routers.
// Sometimes, oftentimes, it will fail if the network is not external.
func SetRouter(routerName, networkName string) error {
	log.DebugLog(log.DebugLevelMexos, "setting router to network", "router", routerName, "network", networkName)
	out, err := TimedOpenStackCommand("openstack", "router", "set", routerName, "--external-gateway", networkName)
	if err != nil {
		err = fmt.Errorf("can't set router %s to %s, %s, %v", routerName, networkName, out, err)
		return err
	}
	return nil
}

//AddRouterSubnet will connect subnet to another network, possibly external, via a router
func AddRouterSubnet(routerName, subnetName string) error {
	log.DebugLog(log.DebugLevelMexos, "adding router to subnet", "router", routerName, "network", subnetName)
	out, err := TimedOpenStackCommand("openstack", "router", "add", "subnet", routerName, subnetName)
	if err != nil {
		err = fmt.Errorf("can't add router %s to subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//RemoveRouterSubnet is useful to remove the router from the subnet before deletion. Otherwise subnet cannot
//  be deleted.
func RemoveRouterSubnet(routerName, subnetName string) error {
	log.DebugLog(log.DebugLevelMexos, "removing subnet from router", "router", routerName, "subnet", subnetName)
	out, err := TimedOpenStackCommand("openstack", "router", "remove", "subnet", routerName, subnetName)
	if err != nil {
		err = fmt.Errorf("can't remove router %s from subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//ListSubnets returns a list of subnets available
func ListSubnets(netName string) ([]OSSubnet, error) {
	var err error
	var out []byte
	if netName != "" {
		out, err = TimedOpenStackCommand("openstack", "subnet", "list", "--network", netName, "-f", "json")
	} else {
		out, err = TimedOpenStackCommand("openstack", "subnet", "list", "-f", "json")
	}
	if err != nil {
		err = fmt.Errorf("can't get a list of subnets, %v", err)
		return nil, err
	}
	subnets := []OSSubnet{}
	err = json.Unmarshal(out, &subnets)
	if err != nil {
		err = fmt.Errorf("can't unmarshal subnets, %v", err)
		return nil, err
	}
	//log.DebugLog(log.DebugLevelMexos, "list subnets", "subnets", subnets)
	return subnets, nil
}

//ListRouters returns a list of routers available
func ListRouters() ([]OSRouter, error) {
	out, err := TimedOpenStackCommand("openstack", "router", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("can't get a list of routers, %s, %v", out, err)
		return nil, err
	}
	routers := []OSRouter{}
	err = json.Unmarshal(out, &routers)
	if err != nil {
		err = fmt.Errorf("can't unmarshal routers, %v", err)
		return nil, err
	}
	log.DebugLog(log.DebugLevelMexos, "list routers", "routers", routers)
	return routers, nil
}

//GetRouterDetail returns details per router
func GetRouterDetail(routerName string) (*OSRouterDetail, error) {
	out, err := TimedOpenStackCommand("openstack", "router", "show", "-f", "json", routerName)
	if err != nil {
		err = fmt.Errorf("can't get router details for %s, %s, %v", routerName, out, err)
		return nil, err
	}
	routerDetail := &OSRouterDetail{}
	err = json.Unmarshal(out, routerDetail)
	if err != nil {
		err = fmt.Errorf("can't unmarshal router detail, %v", err)
		return nil, err
	}
	//log.DebugLog(log.DebugLevelMexos, "router detail", "router detail", routerDetail)
	return routerDetail, nil
}

//CreateServerImage snapshots running service into a qcow2 image
func CreateServerImage(serverName, imageName string) error {
	log.DebugLog(log.DebugLevelMexos, "creating image snapshot from server", "server", serverName, "image", imageName)
	out, err := TimedOpenStackCommand("openstack", "server", "image", "create", serverName, "--name", imageName)
	if err != nil {
		err = fmt.Errorf("can't create image from %s into %s, %s, %v", serverName, imageName, out, err)
		return err
	}
	return nil
}

//CreateImage puts images into glance
func CreateImage(imageName, qcowFile string) error {
	log.DebugLog(log.DebugLevelMexos, "creating image in glance", "image", imageName, "qcow", qcowFile)
	out, err := TimedOpenStackCommand("openstack", "image", "create",
		imageName,
		"--disk-format", "qcow2",
		"--container-format", "bare",
		"--file", qcowFile)
	if err != nil {
		err = fmt.Errorf("can't create image in glace, %s, %s, %s, %v", imageName, qcowFile, out, err)
		return err
	}
	return nil
}

//SaveImage takes the image name available in glance, as a result of for example the above create image.
// It will then save that into a local file. The image transfer happens from glance into your own laptop
// or whatever.
// This can take a while, transferring all the data.
func SaveImage(saveName, imageName string) error {
	log.DebugLog(log.DebugLevelMexos, "saving image", "save name", saveName, "image name", imageName)
	out, err := TimedOpenStackCommand("openstack", "image", "save", "--file", saveName, imageName)
	if err != nil {
		err = fmt.Errorf("can't save image from %s to file %s, %s, %v", imageName, saveName, out, err)
		return err
	}
	return nil
}

//DeleteImage deletes the named image from glance. Sometimes backing store is still busy and
// will refuse to honor the request. Like most things in Openstack, wait for a while and try
// again.
func DeleteImage(imageName string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting image", "name", imageName)
	out, err := TimedOpenStackCommand("openstack", "image", "delete", imageName)
	if err != nil {
		err = fmt.Errorf("can't delete image %s, %s, %v", imageName, out, err)
		return err
	}
	return nil
}

//GetSubnetDetail returns details for the subnet. This is useful when getting router/gateway
//  IP for a given subnet.  The gateway info is used for creating a server.
//  Also useful in general, like other `detail` functions, to get the ID map for the name of subnet.
func GetSubnetDetail(subnetName string) (*OSSubnetDetail, error) {
	out, err := TimedOpenStackCommand("openstack", "subnet", "show", "-f", "json", subnetName)
	if err != nil {
		err = fmt.Errorf("can't get subnet details for %s, %s, %v", subnetName, out, err)
		return nil, err
	}
	subnetDetail := &OSSubnetDetail{}
	err = json.Unmarshal(out, subnetDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal subnet detail, %v", err)
	}
	//log.DebugLog(log.DebugLevelMexos, "get subnet detail", "subnet detail", subnetDetail)
	return subnetDetail, nil
}

//GetNetworkDetail returns details about a network.  It is used, for example, by GetExternalGateway.
func GetNetworkDetail(networkName string) (*OSNetworkDetail, error) {
	out, err := TimedOpenStackCommand("openstack", "network", "show", "-f", "json", networkName)
	if err != nil {
		err = fmt.Errorf("can't get details for network %s, %s, %v", networkName, out, err)
		return nil, err
	}
	networkDetail := &OSNetworkDetail{}
	err = json.Unmarshal(out, networkDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal network detail, %v", err)
	}
	log.DebugLog(log.DebugLevelMexos, "get network detail", "network detail", networkDetail)
	return networkDetail, nil
}

//SetServerProperty sets properties for the server
func SetServerProperty(name, property string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if property == "" {
		return fmt.Errorf("empty property")
	}
	out, err := TimedOpenStackCommand("openstack", "server", "set", "--property", property, name)
	if err != nil {
		return fmt.Errorf("can't set property %s on server %s, %s, %v", property, name, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "set server property", "name", name, "property", property)
	return nil
}

// createHeatStack creates a stack with the given template
func createHeatStack(templateFile string, stackName string) error {
	log.DebugLog(log.DebugLevelMexos, "create heat stack", "template", templateFile, "stackName", stackName)
	_, err := TimedOpenStackCommand("openstack", "stack", "create", "--template", templateFile, stackName)
	if err != nil {
		return fmt.Errorf("error creating heat stack: %s -- %v", templateFile, err)
	}
	return nil
}

// deleteHeatStack delete a stack with the given name
func deleteHeatStack(stackName string) error {
	log.DebugLog(log.DebugLevelMexos, "delete heat stack", "stackName", stackName)
	out, err := TimedOpenStackCommand("openstack", "stack", "delete", stackName)
	if err != nil {
		if strings.Contains("Stack not found", string(out)) {
			log.DebugLog(log.DebugLevelMexos, "stack not found")
			return nil
		}
		log.InfoLog("stack deletion failed", "stackName", stackName, "out", string(out), "err", err)
		return fmt.Errorf("stack deletion failed: %s -- %v", stackName, err)
	}
	return nil
}

// getHeatStackDetail gets details of the provided stack
func getHeatStackDetail(stackName string) (*OSHeatStackDetail, error) {
	out, err := TimedOpenStackCommand("openstack", "stack", "show", "-f", "json", stackName)
	if err != nil {
		err = fmt.Errorf("can't get stack details for %s, %s, %v", stackName, out, err)
		return nil, err
	}
	stackDetail := &OSHeatStackDetail{}
	err = json.Unmarshal(out, stackDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal stack detail, %v", err)
	}
	return stackDetail, nil
}

// Get resource limits
func OSGetLimits(info *edgeproto.CloudletInfo) error {
	log.DebugLog(log.DebugLevelMexos, "GetLimits (Openstack) - Resources info & Supported flavors")
	var limits []OSLimit
	out, err := TimedOpenStackCommand("openstack", "limits", "show", "--absolute", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get limits from openstack, %v", err)
		return err
	}
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	for _, l := range limits {
		if l.Name == "maxTotalRAMSize" {
			info.OsMaxRam = uint64(l.Value)
		} else if l.Name == "maxTotalCores" {
			info.OsMaxVcores = uint64(l.Value)
		} else if l.Name == "maxTotalVolumeGigabytes" {
			info.OsMaxVolGb = uint64(l.Value)
		}
	}

	osflavors, err := ListFlavors()
	if err != nil {
		err = fmt.Errorf("cannot get flavor list from openstack, %v", err)
		return err
	}
	for _, f := range osflavors {
		info.Flavors = append(
			info.Flavors,
			&edgeproto.FlavorInfo{
				Name:  f.Name,
				Vcpus: uint64(f.VCPUs),
				Ram:   uint64(f.RAM),
				Disk:  uint64(f.Disk),
			},
		)
	}
	return nil
}
