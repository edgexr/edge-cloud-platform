package mexos

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func TimedOpenStackCommand(ctx context.Context, name string, a ...string) ([]byte, error) {
	parmstr := ""
	start := time.Now()
	for _, a := range a {
		parmstr += a + " "
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "OpenStack Command Start", "name", name, "parms", parmstr)
	out, err := sh.Command(name, a).CombinedOutput()
	if err != nil {
		log.InfoLog("Openstack command returned error", "parms", parmstr, "err", err, "out", string(out), "elapsed time", time.Since(start))
		return out, err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "OpenStack Command Done", "parmstr", parmstr, "elapsed time", time.Since(start))
	return out, nil

}

//ListServers returns list of servers, KVM instances, running on the system
func ListServers(ctx context.Context) ([]OSServer, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "server", "list", "-f", "json")

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

//ListServers returns list of servers, KVM instances, running on the system
func ListPorts(ctx context.Context) ([]OSPort, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "port", "list", "-f", "json")

	if err != nil {
		err = fmt.Errorf("cannot get port list, %v", err)
		return nil, err
	}
	var ports []OSPort
	err = json.Unmarshal(out, &ports)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return ports, nil
}

//ListImages lists avilable images in glance
func ListImages(ctx context.Context) ([]OSImage, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "image", "list", "-f", "json")
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
	log.SpanLog(ctx, log.DebugLevelMexos, "list images", "images", images)
	return images, nil
}

//GetImageDetail show of a given image from Glance
func GetImageDetail(ctx context.Context, name string) (*OSImageDetail, error) {
	out, err := TimedOpenStackCommand(
		ctx, "openstack", "image", "show", name, "-f", "json",
		"-c", "id",
		"-c", "status",
		"-c", "updated_at",
		"-c", "checksum",
	)
	if err != nil {
		err = fmt.Errorf("cannot get image Detail for %s, %s, %v", name, string(out), err)
		return nil, err
	}
	var imageDetail OSImageDetail
	err = json.Unmarshal(out, &imageDetail)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "show image Detail", "Detail", imageDetail)
	return &imageDetail, nil
}

//ListNetworks lists networks known to the platform. Some created by the operator, some by users.
func ListNetworks(ctx context.Context) ([]OSNetwork, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "network", "list", "-f", "json")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "network list failed", "out", out)
		err = fmt.Errorf("cannot get network list, %v", err)
		return nil, err
	}
	var networks []OSNetwork
	err = json.Unmarshal(out, &networks)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "list networks", "networks", networks)
	return networks, nil
}

//ShowFlavor returns the details of a given flavor.
// If the flavor has any properties set, these are returned as well
func ShowFlavor(ctx context.Context, flavor string) (details string, properties string, err error) {

	out, err := TimedOpenStackCommand(ctx, "openstack", "flavor", "show", flavor, "-f", "json")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "flavor show failed", "out", out)
		fmt.Printf("Timed Op return error %d\n", err)
		return "", "", err
	}
	s := strings.Index(string(out), "properties")
	s += len("properties") + 2
	ms := cloudcommon.QuotedStringRegex.FindAllString(string(out[s:]), -1)
	ss := make([]string, len(ms))
	for i, m := range ms {
		ss[i] = m[1 : len(m)-1]
	}
	return string(out), ss[0], err
}

//ListFlavors lists flavors known to the platform.   The ones matching the flavorMatchPattern are returned
func ListFlavors(ctx context.Context) ([]OSFlavor, error) {
	flavorMatchPattern := GetCloudletFlavorMatchPattern()
	r, err := regexp.Compile(flavorMatchPattern)
	if err != nil {
		return nil, fmt.Errorf("Cannot compile flavor match pattern")
	}
	out, err := TimedOpenStackCommand(ctx, "openstack", "flavor", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get flavor list, %v", err)
		return nil, err
	}
	var flavors []OSFlavor
	var flavorsMatched []OSFlavor
	err = json.Unmarshal(out, &flavors)

	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	for _, f := range flavors {
		if r.MatchString(f.Name) {
			flavorsMatched = append(flavorsMatched, f)
		}
	}
	return flavorsMatched, nil
}

func ListFloatingIPs(ctx context.Context) ([]OSFloatingIP, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "floating", "ip", "list", "-f", "json")
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
func CreateServer(ctx context.Context, opts *OSServerOpt) error {
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
	log.SpanLog(ctx, log.DebugLevelMexos, "creating server with args", "iargs", iargs)

	//log.SpanLog(ctx,log.DebugLevelMexos, "openstack create server", "opts", opts, "iargs", iargs)
	out, err := TimedOpenStackCommand(ctx, "openstack", iargs...)
	if err != nil {
		err = fmt.Errorf("cannot create server, %v, '%s'", err, out)
		return err
	}
	return nil
}

// GetServerDetails returns details of the KVM instance
func GetServerDetails(ctx context.Context, name string) (*OSServerDetail, error) {
	active := false
	srvDetail := &OSServerDetail{}
	for i := 0; i < 10; i++ {
		out, err := TimedOpenStackCommand(ctx, "openstack", "server", "show", "-f", "json", name)
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
		log.SpanLog(ctx, log.DebugLevelMexos, "wait for server to become ACTIVE", "server detail", srvDetail)
		time.Sleep(30 * time.Second)
	}
	if !active {
		return nil, fmt.Errorf("while getting server detail, waited but server %s is too slow getting to active state", name)
	}
	//log.SpanLog(ctx,log.DebugLevelMexos, "server detail", "server detail", srvDetail)
	return srvDetail, nil
}

// GetPortDetails gets details of the specified port
func GetPortDetails(ctx context.Context, name string) (*OSPortDetail, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "get port details", "name", name)
	portDetail := &OSPortDetail{}

	out, err := TimedOpenStackCommand(ctx, "openstack", "port", "show", name, "-f", "json")
	if err != nil {
		err = fmt.Errorf("can't get port detail for port: %s, %s, %v", name, out, err)
		return nil, err
	}
	err = json.Unmarshal(out, &portDetail)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "port unmarshal failed", "err", err)
		err = fmt.Errorf("can't unmarshal port, %v", err)
		return nil, err
	}
	return portDetail, nil
}

// AttachPortToServer attaches a port to a server
func AttachPortToServer(ctx context.Context, serverName, portName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "AttachPortToServer", "serverName", serverName, "portName", portName)

	out, err := TimedOpenStackCommand(ctx, "openstack", "server", "add", "port", serverName, portName)
	if err != nil {
		if strings.Contains(string(out), "still in use") {
			// port already attached
			log.SpanLog(ctx, log.DebugLevelMexos, "port already attached", "serverName", serverName, "portName", portName, "out", out, "err", err)
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelMexos, "can't attach port", "serverName", serverName, "portName", portName, "out", out, "err", err)
		err = fmt.Errorf("can't attach port: %s, %s, %v", portName, out, err)
		return err
	}
	return nil
}

// DetachPortFromServer removes a port from a server
func DetachPortFromServer(ctx context.Context, serverName, portName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "DetachPortFromServer", "serverName", serverName, "portName", portName)

	out, err := TimedOpenStackCommand(ctx, "openstack", "server", "remove", "port", serverName, portName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "can't remove port", "serverName", serverName, "portName", portName, "out", out, "err", err)
		if strings.Contains(string(out), "No Port found") {
			// when ports are removed they are detached from any server they are connected to.
			log.SpanLog(ctx, log.DebugLevelMexos, "port is gone", "portName", portName)
			err = nil
		} else {
			log.SpanLog(ctx, log.DebugLevelMexos, "can't remove port", "serverName", serverName, "portName", portName, "out", out, "err", err)
		}
		return err
	}
	return nil
}

//DeleteServer destroys a KVM instance
//  sometimes it is not possible to destroy. Like most things in Openstack, try again.
func DeleteServer(ctx context.Context, id string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "deleting server", "id", id)
	out, err := TimedOpenStackCommand(ctx, "openstack", "server", "delete", id)
	if err != nil {
		err = fmt.Errorf("can't delete server %s, %s, %v", id, out, err)
		return err
	}
	return nil
}

// CreateNetwork creates a network with a name.
func CreateNetwork(ctx context.Context, name string, netType string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "creating network", "network", name)
	args := []string{"network", "create"}
	if netType != "" {
		args = append(args, []string{"--provider-network-type", netType}...)
	}
	args = append(args, name)
	out, err := TimedOpenStackCommand(ctx, "openstack", args...)
	if err != nil {
		err = fmt.Errorf("can't create network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//DeleteNetwork destroys a named network
//  Sometimes it will fail. Openstack will refuse if there are resources attached.
func DeleteNetwork(ctx context.Context, name string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "deleting network", "network", name)
	out, err := TimedOpenStackCommand(ctx, "openstack", "network", "delete", name)
	if err != nil {
		err = fmt.Errorf("can't delete network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//CreateSubnet creates a subnet within a network. A subnet is assigned ranges. Optionally DHCP can be enabled.
func CreateSubnet(ctx context.Context, netRange, networkName, gatewayAddr, subnetName string, dhcpEnable bool) error {
	var dhcpFlag string
	if dhcpEnable {
		dhcpFlag = "--dhcp"
	} else {
		dhcpFlag = "--no-dhcp"
	}
	out, err := TimedOpenStackCommand(ctx, "openstack", "subnet", "create",
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
				sd, serr := GetSubnetDetail(ctx, subnetName)
				if serr != nil {
					return fmt.Errorf("cannot get subnet detail for %s, while fixing overlap error, %v", subnetName, serr)
				}
				log.SpanLog(ctx, log.DebugLevelMexos, "create subnet, existing subnet detail", "subnet detail", sd)

				//XXX do more validation

				log.SpanLog(ctx, log.DebugLevelMexos, "create subnet, reusing existing subnet", "result", out, "error", err)
				return nil
			}
		}
		err = fmt.Errorf("can't create subnet %s, %s, %v", subnetName, out, err)
		return err
	}
	return nil
}

//DeleteSubnet deletes the subnet. If this fails, remove any attached resources, like router, and try again.
func DeleteSubnet(ctx context.Context, subnetName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "deleting subnet", "name", subnetName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "subnet", "delete", subnetName)
	if err != nil {
		err = fmt.Errorf("can't delete subnet %s, %s, %v", subnetName, out, err)
		return err
	}
	return nil
}

//CreateRouter creates new router. A router can be attached to network and subnets.
func CreateRouter(ctx context.Context, routerName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "creating router", "name", routerName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "router", "create", routerName)
	if err != nil {
		err = fmt.Errorf("can't create router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//DeleteRouter removes the named router. The router needs to not be in use at the time of deletion.
func DeleteRouter(ctx context.Context, routerName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "deleting router", "name", routerName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "router", "delete", routerName)
	if err != nil {
		err = fmt.Errorf("can't delete router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//SetRouter assigns the router to a particular network. The network needs to be attached to
// a real external network. This is intended only for routing to external network for now. No internal routers.
// Sometimes, oftentimes, it will fail if the network is not external.
func SetRouter(ctx context.Context, routerName, networkName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "setting router to network", "router", routerName, "network", networkName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "router", "set", routerName, "--external-gateway", networkName)
	if err != nil {
		err = fmt.Errorf("can't set router %s to %s, %s, %v", routerName, networkName, out, err)
		return err
	}
	return nil
}

//AddRouterSubnet will connect subnet to another network, possibly external, via a router
func AddRouterSubnet(ctx context.Context, routerName, subnetName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "adding router to subnet", "router", routerName, "network", subnetName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "router", "add", "subnet", routerName, subnetName)
	if err != nil {
		err = fmt.Errorf("can't add router %s to subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//RemoveRouterSubnet is useful to remove the router from the subnet before deletion. Otherwise subnet cannot
//  be deleted.
func RemoveRouterSubnet(ctx context.Context, routerName, subnetName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "removing subnet from router", "router", routerName, "subnet", subnetName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "router", "remove", "subnet", routerName, subnetName)
	if err != nil {
		err = fmt.Errorf("can't remove router %s from subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//ListSubnets returns a list of subnets available
func ListSubnets(ctx context.Context, netName string) ([]OSSubnet, error) {
	var err error
	var out []byte
	if netName != "" {
		out, err = TimedOpenStackCommand(ctx, "openstack", "subnet", "list", "--network", netName, "-f", "json")
	} else {
		out, err = TimedOpenStackCommand(ctx, "openstack", "subnet", "list", "-f", "json")
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
	//log.SpanLog(ctx,log.DebugLevelMexos, "list subnets", "subnets", subnets)
	return subnets, nil
}

//ListRouters returns a list of routers available
func ListRouters(ctx context.Context) ([]OSRouter, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "router", "list", "-f", "json")
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
	log.SpanLog(ctx, log.DebugLevelMexos, "list routers", "routers", routers)
	return routers, nil
}

//GetRouterDetail returns details per router
func GetRouterDetail(ctx context.Context, routerName string) (*OSRouterDetail, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "router", "show", "-f", "json", routerName)
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
	//log.SpanLog(ctx,log.DebugLevelMexos, "router detail", "router detail", routerDetail)
	return routerDetail, nil
}

//CreateServerImage snapshots running service into a qcow2 image
func CreateServerImage(ctx context.Context, serverName, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "creating image snapshot from server", "server", serverName, "image", imageName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "server", "image", "create", serverName, "--name", imageName)
	if err != nil {
		err = fmt.Errorf("can't create image from %s into %s, %s, %v", serverName, imageName, out, err)
		return err
	}
	return nil
}

//CreateImage puts images into glance
func CreateImage(ctx context.Context, imageName, qcowFile string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "creating image in glance", "image", imageName, "qcow", qcowFile)
	out, err := TimedOpenStackCommand(ctx, "openstack", "image", "create",
		imageName,
		"--disk-format", "qcow2",
		"--container-format", "bare",
		"--file", qcowFile)
	if err != nil {
		err = fmt.Errorf("can't create image in glance, %s, %s, %s, %v", imageName, qcowFile, out, err)
		return err
	}
	return nil
}

//CreateImageFromUrl downloads image from URL and then puts into glance
func CreateImageFromUrl(ctx context.Context, imageName, imageUrl, md5Sum string) error {
	fileExt, err := cloudcommon.GetFileNameWithExt(imageUrl)
	if err != nil {
		return err
	}
	filePath := "/tmp/" + fileExt
	err = DownloadFile(ctx, imageUrl, filePath)
	if err != nil {
		return fmt.Errorf("error downloading image from %s, %v", imageUrl, err)
	}
	// Verify checksum
	if md5Sum != "" {
		fileMd5Sum, err := Md5SumFile(filePath)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelMexos, "verify md5sum", "downloaded-md5sum", fileMd5Sum, "actual-md5sum", md5Sum)
		if fileMd5Sum != md5Sum {
			return fmt.Errorf("mismatch in md5sum")
		}
	}

	err = CreateImage(ctx, imageName, filePath)
	if delerr := DeleteFile(filePath); delerr != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "delete file failed", "filePath", filePath)
	}
	if err != nil {
		return fmt.Errorf("error creating image %v", err)
	}
	return err
}

//SaveImage takes the image name available in glance, as a result of for example the above create image.
// It will then save that into a local file. The image transfer happens from glance into your own laptop
// or whatever.
// This can take a while, transferring all the data.
func SaveImage(ctx context.Context, saveName, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "saving image", "save name", saveName, "image name", imageName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "image", "save", "--file", saveName, imageName)
	if err != nil {
		err = fmt.Errorf("can't save image from %s to file %s, %s, %v", imageName, saveName, out, err)
		return err
	}
	return nil
}

//DeleteImage deletes the named image from glance. Sometimes backing store is still busy and
// will refuse to honor the request. Like most things in Openstack, wait for a while and try
// again.
func DeleteImage(ctx context.Context, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "deleting image", "name", imageName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "image", "delete", imageName)
	if err != nil {
		err = fmt.Errorf("can't delete image %s, %s, %v", imageName, out, err)
		return err
	}
	return nil
}

//GetSubnetDetail returns details for the subnet. This is useful when getting router/gateway
//  IP for a given subnet.  The gateway info is used for creating a server.
//  Also useful in general, like other `detail` functions, to get the ID map for the name of subnet.
func GetSubnetDetail(ctx context.Context, subnetName string) (*OSSubnetDetail, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "subnet", "show", "-f", "json", subnetName)
	if err != nil {
		err = fmt.Errorf("can't get subnet details for %s, %s, %v", subnetName, out, err)
		return nil, err
	}
	subnetDetail := &OSSubnetDetail{}
	err = json.Unmarshal(out, subnetDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal subnet detail, %v", err)
	}
	//log.SpanLog(ctx,log.DebugLevelMexos, "get subnet detail", "subnet detail", subnetDetail)
	return subnetDetail, nil
}

//GetNetworkDetail returns details about a network.  It is used, for example, by GetExternalGateway.
func GetNetworkDetail(ctx context.Context, networkName string) (*OSNetworkDetail, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "network", "show", "-f", "json", networkName)
	if err != nil {
		err = fmt.Errorf("can't get details for network %s, %s, %v", networkName, out, err)
		return nil, err
	}
	networkDetail := &OSNetworkDetail{}
	err = json.Unmarshal(out, networkDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal network detail, %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "get network detail", "network detail", networkDetail)
	return networkDetail, nil
}

//SetServerProperty sets properties for the server
func SetServerProperty(ctx context.Context, name, property string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if property == "" {
		return fmt.Errorf("empty property")
	}
	out, err := TimedOpenStackCommand(ctx, "openstack", "server", "set", "--property", property, name)
	if err != nil {
		return fmt.Errorf("can't set property %s on server %s, %s, %v", property, name, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "set server property", "name", name, "property", property)
	return nil
}

// createHeatStack creates a stack with the given template
func createHeatStack(ctx context.Context, templateFile string, stackName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "create heat stack", "template", templateFile, "stackName", stackName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "stack", "create", "--template", templateFile, stackName)
	if err != nil {
		return fmt.Errorf("error creating heat stack: %s, %s -- %v", templateFile, string(out), err)
	}
	return nil
}

func updateHeatStack(ctx context.Context, templateFile string, stackName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "update heat stack", "template", templateFile, "stackName", stackName)
	_, err := TimedOpenStackCommand(ctx, "openstack", "stack", "update", "--template", templateFile, stackName)
	if err != nil {
		return fmt.Errorf("error udpating heat stack: %s -- %v", templateFile, err)
	}
	return nil
}

// deleteHeatStack delete a stack with the given name
func deleteHeatStack(ctx context.Context, stackName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "delete heat stack", "stackName", stackName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "stack", "delete", stackName)
	if err != nil {
		if strings.Contains("Stack not found", string(out)) {
			log.SpanLog(ctx, log.DebugLevelMexos, "stack not found")
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelMexos, "stack deletion failed", "stackName", stackName, "out", string(out), "err", err)
		if strings.Contains(string(out), "Stack not found") {
			log.SpanLog(ctx, log.DebugLevelMexos, "stack already deleted", "stackName", stackName)
			return nil
		}
		return fmt.Errorf("stack deletion failed: %s, %s %v", stackName, out, err)
	}
	return nil
}

// getHeatStackDetail gets details of the provided stack
func getHeatStackDetail(ctx context.Context, stackName string) (*OSHeatStackDetail, error) {
	out, err := TimedOpenStackCommand(ctx, "openstack", "stack", "show", "-f", "json", stackName)
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
func OSGetLimits(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "GetLimits (Openstack) - Resources info & Supported flavors")
	var limits []OSLimit
	out, err := TimedOpenStackCommand(ctx, "openstack", "limits", "show", "--absolute", "-f", "json")
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

	finfo, err := GetFlavorInfo(ctx)
	if err != nil {
		return err
	}
	info.Flavors = finfo
	return nil
}

func OSGetAllLimits(ctx context.Context) ([]OSLimit, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "GetLimits (Openstack) - Resources info and usage")
	var limits []OSLimit
	out, err := TimedOpenStackCommand(ctx, "openstack", "limits", "show", "--absolute", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get limits from openstack, %v", err)
		return nil, err
	}
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return limits, nil
}

func GetFlavorInfo(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	osflavors, err := ListFlavors(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get flavors, %v", err.Error())
	}
	if len(osflavors) == 0 {
		return nil, fmt.Errorf("no flavors found")
	}
	var finfo []*edgeproto.FlavorInfo
	for _, f := range osflavors {
		finfo = append(
			finfo,
			&edgeproto.FlavorInfo{
				Name:  f.Name,
				Vcpus: uint64(f.VCPUs),
				Ram:   uint64(f.RAM),
				Disk:  uint64(f.Disk)},
		)
	}
	return finfo, nil
}

func OSGetConsoleUrl(ctx context.Context, serverName string) (*OSConsoleUrl, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "get console url", "server", serverName)
	out, err := TimedOpenStackCommand(ctx, "openstack", "console", "url", "show", "-f", "json", "-c", "url", "--novnc", serverName)
	if err != nil {
		err = fmt.Errorf("can't get console url details for %s, %s, %v", serverName, out, err)
		return nil, err
	}
	consoleUrl := &OSConsoleUrl{}
	err = json.Unmarshal(out, consoleUrl)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal console url output, %v", err)
	}
	return consoleUrl, nil
}

// Finds a resource by name by instance id.
// There are resources that are metered for instance-id, which are resources of their own
// The examples are instance_network_interface and instance_disk
// Openstack example call:
//   <openstack metric resource search --type instance_network_interface instance_id=dc32daa6-0d0a-4512-a9fa-2b989e913014>
// We only use the the first found result
func OSFindResourceByInstId(ctx context.Context, resourceType string, instId string) (*OSMetricResource, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "find resource for instance Id", "id", instId,
		"resource", resourceType)
	osRes := []OSMetricResource{}
	instArg := fmt.Sprintf("instance_id=%s", instId)
	out, err := TimedOpenStackCommand(ctx, "openstack", "metric", "resource", "search",
		"-f", "json", "--type", resourceType, instArg)
	if err != nil {
		err = fmt.Errorf("can't find resource %s, for %s, %s %v", resourceType, instId, out, err)
		return nil, err
	}
	err = json.Unmarshal(out, &osRes)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal Metric Resource, %v", err)
		return nil, err
	}
	if len(osRes) != 1 {
		return nil, fmt.Errorf("Unexpected Number of Meters found")
	}
	return &osRes[0], nil
}

// Get openstack metrics from ceilometer tsdb
// Example openstack call:
//   <openstack metric measures show --resource-id a9bf10cf-a709-5a47-8b69-da920b8f65cd network.incoming.bytes>
// This will return a range of measurements from the startTime
func OSGetMetricsRangeForId(ctx context.Context, resId string, metric string, startTime time.Time) ([]OSMetricMeasurement, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "get measure for Id", "id", resId, "metric", metric)
	measurements := []OSMetricMeasurement{}

	startStr := startTime.Format(time.RFC3339)

	out, err := TimedOpenStackCommand(ctx, "openstack", "metric", "measures", "show",
		"-f", "json", "--start", startStr, "--resource-id", resId, metric)
	if err != nil {
		err = fmt.Errorf("can't get measurements %s, for %s, %s %v", metric, resId, out, err)
		return []OSMetricMeasurement{}, err
	}
	err = json.Unmarshal(out, &measurements)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal measurements, %v", err)
		return []OSMetricMeasurement{}, err
	}
	// No value, means we don't need to write it
	if len(measurements) == 0 {
		return []OSMetricMeasurement{}, fmt.Errorf("No values for the metric")
	}
	return measurements, nil
}
