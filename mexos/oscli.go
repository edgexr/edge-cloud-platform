package mexos

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

//ListServers returns list of servers, KVM instances, running on the system
func ListServers(mf *Manifest) ([]OSServer, error) {
	out, err := sh.Command("openstack", "server", "list", "-f", "json").Output()
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
	log.DebugLog(log.DebugLevelMexos, "list servers", "servers", servers)
	return servers, nil
}

//ListImages lists avilable images in glance
func ListImages(mf *Manifest) ([]OSImage, error) {
	out, err := sh.Command("openstack", "image", "list", "-f", "json").Output()
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
func ListNetworks(mf *Manifest) ([]OSNetwork, error) {
	out, err := sh.Command("openstack", "network", "list", "-f", "json").Output()
	if err != nil {
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
func ListFlavors(mf *Manifest) ([]OSFlavor, error) {
	out, err := sh.Command("openstack", "flavor", "list", "-f", "json").Output()
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
	log.DebugLog(log.DebugLevelMexos, "list flavors", flavors)
	return flavors, nil
}

//CreateServer instantiates a new server instance, which is a KVM instance based on a qcow2 image from glance
func CreateServer(mf *Manifest, opts *OSServerOpt) error {
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
	iargs := make([]interface{}, len(args))
	for i, v := range args {
		iargs[i] = v
	}
	log.DebugLog(log.DebugLevelMexos, "openstack create server", "opts", opts, "iargs", iargs)
	out, err := sh.Command("openstack", iargs...).Output()
	if err != nil {
		err = fmt.Errorf("cannot create server, %v, '%s'", err, out)
		return err
	}
	return nil
}

// GetServerDetails returns details of the KVM instance
func GetServerDetails(mf *Manifest, name string) (*OSServerDetail, error) {
	active := false
	srvDetail := &OSServerDetail{}
	for i := 0; i < 10; i++ {
		out, err := sh.Command("openstack", "server", "show", "-f", "json", name).Output()
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
	log.DebugLog(log.DebugLevelMexos, "server detail", "server detail", srvDetail)
	return srvDetail, nil
}

//DeleteServer destroys a KVM instance
//  sometimes it is not possible to destroy. Like most things in Openstack, try again.
func DeleteServer(mf *Manifest, id string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting server", "id", id)
	out, err := sh.Command("openstack", "server", "delete", id).Output()
	if err != nil {
		err = fmt.Errorf("can't delete server %s, %s, %v", id, out, err)
		return err
	}
	return nil
}

// CreateNetwork creates a network with a name.
func CreateNetwork(mf *Manifest, name string) error {
	log.DebugLog(log.DebugLevelMexos, "creating network", "network", name)
	out, err := sh.Command("openstack", "network", "create", name).Output()
	if err != nil {
		err = fmt.Errorf("can't create network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//DeleteNetwork destroys a named network
//  Sometimes it will fail. Openstack will refuse if there are resources attached.
func DeleteNetwork(mf *Manifest, name string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting network", "network", name)
	out, err := sh.Command("openstack", "network", "delete", name).Output()
	if err != nil {
		err = fmt.Errorf("can't delete network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//CreateSubnet creates a subnet within a network. A subnet is assigned ranges. Optionally DHCP can be enabled.
func CreateSubnet(mf *Manifest, netRange, networkName, gatewayAddr, subnetName string, dhcpEnable bool) error {
	var dhcpFlag string
	if dhcpEnable {
		dhcpFlag = "--dhcp"
	} else {
		dhcpFlag = "--no-dhcp"
	}
	out, err := sh.Command("openstack", "subnet", "create",
		"--subnet-range", netRange, // e.g. 10.101.101.0/24
		"--network", networkName, // mex-k8s-net-1
		dhcpFlag,
		"--gateway", gatewayAddr, // e.g. 10.101.101.1
		subnetName).CombinedOutput() // e.g. mex-k8s-subnet-1
	if err != nil {
		nerr := &NeutronErrorType{}
		if ix := strings.Index(string(out), `{"NeutronError":`); ix > 0 {
			neutronErr := out[ix:]
			if jerr := json.Unmarshal(neutronErr, nerr); jerr != nil {
				err = fmt.Errorf("can't create subnet %s, %s, %v, error while parsing neutron error, %v", subnetName, out, err, jerr)
				return err
			}
			if strings.Index(nerr.NeutronError.Message, "overlap") > 0 {
				sd, serr := GetSubnetDetail(mf, subnetName)
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
func DeleteSubnet(mf *Manifest, subnetName string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting subnet", "name", subnetName)
	out, err := sh.Command("openstack", "subnet", "delete", subnetName).Output()
	if err != nil {
		err = fmt.Errorf("can't delete subnet %s, %s, %v", subnetName, out, err)
		return err
	}
	return nil
}

//CreateRouter creates new router. A router can be attached to network and subnets.
func CreateRouter(mf *Manifest, routerName string) error {
	log.DebugLog(log.DebugLevelMexos, "creating router", "name", routerName)
	out, err := sh.Command("openstack", "router", "create", routerName).Output()
	if err != nil {
		err = fmt.Errorf("can't create router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//DeleteRouter removes the named router. The router needs to not be in use at the time of deletion.
func DeleteRouter(mf *Manifest, routerName string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting router", "name", routerName)
	out, err := sh.Command("openstack", "router", "delete", routerName).Output()
	if err != nil {
		err = fmt.Errorf("can't delete router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//SetRouter assigns the router to a particular network. The network needs to be attached to
// a real external network. This is intended only for routing to external network for now. No internal routers.
// Sometimes, oftentimes, it will fail if the network is not external.
func SetRouter(mf *Manifest, routerName, networkName string) error {
	log.DebugLog(log.DebugLevelMexos, "setting router to network", "router", routerName, "network", networkName)
	out, err := sh.Command("openstack", "router", "set", routerName, "--external-gateway", networkName).Output()
	if err != nil {
		err = fmt.Errorf("can't set router %s to %s, %s, %v", routerName, networkName, out, err)
		return err
	}
	return nil
}

//AddRouterSubnet will connect subnet to another network, possibly external, via a router
func AddRouterSubnet(mf *Manifest, routerName, subnetName string) error {
	log.DebugLog(log.DebugLevelMexos, "adding router to subnet", "router", routerName, "network", subnetName)
	out, err := sh.Command("openstack", "router", "add", "subnet", routerName, subnetName).Output()
	if err != nil {
		err = fmt.Errorf("can't add router %s to subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//RemoveRouterSubnet is useful to remove the router from the subnet before deletion. Otherwise subnet cannot
//  be deleted.
func RemoveRouterSubnet(mf *Manifest, routerName, subnetName string) error {
	log.DebugLog(log.DebugLevelMexos, "removing subnet from router", "router", routerName, "subnet", subnetName)
	out, err := sh.Command("openstack", "router", "remove", "subnet", routerName, subnetName).Output()
	if err != nil {
		err = fmt.Errorf("can't remove router %s from subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//ListSubnets returns a list of subnets available
func ListSubnets(mf *Manifest, netName string) ([]OSSubnet, error) {
	var err error
	var out []byte

	if netName != "" {
		out, err = sh.Command("openstack", "subnet", "list", "--network", netName, "-f", "json").Output()
	} else {
		out, err = sh.Command("openstack", "subnet", "list", "-f", "json").Output()
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
	log.DebugLog(log.DebugLevelMexos, "list subnets", "subnets", subnets)
	return subnets, nil
}

//ListRouters returns a list of routers available
func ListRouters(mf *Manifest) ([]OSRouter, error) {
	out, err := sh.Command("openstack", "router", "list", "-f", "json").Output()
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
func GetRouterDetail(mf *Manifest, routerName string) (*OSRouterDetail, error) {
	out, err := sh.Command("openstack", "router", "show", "-f", "json", routerName).Output()
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
	log.DebugLog(log.DebugLevelMexos, "router detail", "router detail", routerDetail)
	return routerDetail, nil
}

//CreateServerImage snapshots running service into a qcow2 image
func CreateServerImage(mf *Manifest, serverName, imageName string) error {
	log.DebugLog(log.DebugLevelMexos, "creating image snapshot from server", "server", serverName, "image", imageName)
	out, err := sh.Command("openstack", "server", "image", "create", serverName, "--name", imageName).Output()
	if err != nil {
		err = fmt.Errorf("can't create image from %s into %s, %s, %v", serverName, imageName, out, err)
		return err
	}
	return nil
}

//CreateImage puts images into glance
func CreateImage(mf *Manifest, imageName, qcowFile string) error {
	log.DebugLog(log.DebugLevelMexos, "creating image in glance", "image", imageName, "qcow", qcowFile)
	out, err := sh.Command("openstack", "image", "create",
		imageName,
		"--disk-format", "qcow2",
		"--container-format", "bare",
		"--file", qcowFile).Output()
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
func SaveImage(mf *Manifest, saveName, imageName string) error {
	log.DebugLog(log.DebugLevelMexos, "saving image", "save name", saveName, "image name", imageName)
	out, err := sh.Command("openstack", "image", "save", "--file", saveName, imageName).Output()
	if err != nil {
		err = fmt.Errorf("can't save image from %s to file %s, %s, %v", imageName, saveName, out, err)
		return err
	}
	return nil
}

//DeleteImage deletes the named image from glance. Sometimes backing store is still busy and
// will refuse to honor the request. Like most things in Openstack, wait for a while and try
// again.
func DeleteImage(mf *Manifest, imageName string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting image", "name", imageName)
	out, err := sh.Command("openstack", "image", "delete", imageName).Output()
	if err != nil {
		err = fmt.Errorf("can't delete image %s, %s, %v", imageName, out, err)
		return err
	}
	return nil
}

//GetSubnetDetail returns details for the subnet. This is useful when getting router/gateway
//  IP for a given subnet.  The gateway info is used for creating a server.
//  Also useful in general, like other `detail` functions, to get the ID map for the name of subnet.
func GetSubnetDetail(mf *Manifest, subnetName string) (*OSSubnetDetail, error) {
	out, err := sh.Command("openstack", "subnet", "show", "-f", "json", subnetName).Output()
	if err != nil {
		err = fmt.Errorf("can't get subnet details for %s, %s, %v", subnetName, out, err)
		return nil, err
	}
	subnetDetail := &OSSubnetDetail{}
	err = json.Unmarshal(out, subnetDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal subnet detail, %v", err)
	}
	log.DebugLog(log.DebugLevelMexos, "get subnet detail", "subnet detail", subnetDetail)
	return subnetDetail, nil
}

//GetNetworkDetail returns details about a network.  It is used, for example, by GetExternalGateway.
func GetNetworkDetail(mf *Manifest, networkName string) (*OSNetworkDetail, error) {
	out, err := sh.Command("openstack", "network", "show", "-f", "json", networkName).Output()
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
func SetServerProperty(mf *Manifest, name, property string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if property == "" {
		return fmt.Errorf("empty property")
	}
	out, err := sh.Command("openstack", "server", "set", "--property", property, name).Output()
	if err != nil {
		return fmt.Errorf("can't set property %s on server %s, %s, %v", property, name, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "set server property", "name", name, "property", property)
	return nil
}
