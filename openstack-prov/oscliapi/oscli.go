package oscli

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/codeskyblue/go-sh"
	log "github.com/sirupsen/logrus"
)

// There are issues with x509 certfication and token retrieval when using ../api
// with certain Openstack cloudlets. The issues are handled correctly by
// openstack CLI python code. But not in the gophercloud library.
// So the existence of this code is for: (1) avoid all the issues that are
// time-wasting and go directly to something that always works,
// (2) show clear examples, as a tutorial, to those who are not familiar
// with openstack.

// Limit name,value pairs of Openstack tenant level limits. The only platform
// level stats available to us reliably at some cloudlets.
type Limit struct {
	Name  string
	Value int
}

// Server is output of 'openstack server list'.  In Openstack, 'server' means
//  an instance of KVM.
type Server struct {
	Status, Name, Image, ID, Flavor, Networks string
}

// ServerOpt is used to specify options when creating servers.
type ServerOpt struct {
	AvailabilityZone    string //XXX not used yet
	Name, Image, Flavor string
	UserData            string
	NetIDs              []string
	Properties          []string
}

// ServerDetail  is used with output of 'openstack server show' to list
//   gory details per server.
type ServerDetail struct {
	TaskState        string `json:"OS-EXT-STS:task_state"`
	Addresses        string `json:"addresses"`
	Image            string `json:"image"`
	VMState          string `json:"OS-EXT-STS:vm_state"`
	LaunchedAt       string `json:"OS-SRV-USG:launched_at"`
	Flavor           string `json:"flavor"`
	ID               string `json:"id"`
	SecurityGroups   string `json:"security_groups"`
	VolumesAttached  string `json:"volumes_attached"`
	UserID           string `json:"user_id"`
	DiskConfig       string `json:"OS-DCF:diskConfig"`
	AccessIPv4       string `json:"accessIPv4"`
	AccessIPv6       string `json:"accessIPv6"`
	Progress         int    `json:"progress"`
	PowerState       string `json:"OS-EXT-STS:power_state"`
	ProjectID        string `json:"project_id"`
	ConfigDrive      string `json:"config_drive"`
	Status           string `json:"status"`
	Updated          string `json:"updated"`
	HostID           string `json:"hostId"`
	TerminatedAt     string `json:"OS-SRV-USG:terminated_at"`
	KeyName          string `json:"key_name"`
	AvailabilityZone string `json:"OS-EXT-AZ:availability_zone"`
	Name             string `json:"name"`
	Created          string `json:"created"`
	Properties       string `json:"properties"`
}

// Image is used with 'openstack image list'
type Image struct {
	Status, ID, Name string
}

// Network is used with 'openstack network list'
//   A network in openstack is created as needed. Some are
//   created by the provider and has extra features. Such
//   as external connectivity.
type Network struct {
	Subnets, ID, Name string
}

// NetworkDetail has a informational data for the network.
type NetworkDetail struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	ProviderPhysicalNetwork string `json:"provider:physical_network"`
	IPv6AddressScope        string `json:"ipv6_address_scope"`
	DNSDomain               string `json:"dns_domain"`
	IsVLANTransparent       string `json:"is_vlan_transparent"`
	ProviderNetworkType     string `json:"provider:network_type"`
	External                string `json:"router:external"`
	AvailabilityZoneHints   string `json:"availability_zone_hints"`
	AvailabilityZones       string `json:"availability_zones"`
	Segments                string `json:"segments"`
	IPv4AddressScope        string `json:"ipv4_address_scope"`
	ProjectID               string `json:"project_id"`
	Status                  string `json:"status"`
	Subnets                 string `json:"subnets"`
	Description             string `json:"description"`
	Tags                    string `json:"tags"`
	UpdatedAt               string `json:"updated_at"`
	ProviderSegmentationID  string `json:"provider:segmentation_id"`
	QOSPolicyID             string `json:"qos_policy_id"`
	AdminStateUp            string `json:"admin_state_up"`
	CreatedAt               string `json:"created_at"`
	RevisionNumber          int    `json:"revision_number"`
	MTU                     int    `json:"mtu"`
	PortSecurityEnabled     bool   `json:"port_security_enabled"`
	Shared                  bool   `json:"shared"`
	IsDefault               bool   `json:"is_default"`
}

// Flavor is used with 'openstack flavor list'
type Flavor struct {
	Name, ID                    string
	RAM, Ephemeral, VCPUs, Disk int
}

// Subnet is used with 'openstack subnet list'
//  In openstack, each 'network' contains 'subnets'.
//  Networks have higher abstractions. The subnets
//  actually contain network ranges, etc.
type Subnet struct {
	Name, ID, Network, Subnet string
}

//SubnetDetail contains details about a given subnet.
//  ID,Name and  GatewayIP are useful.
type SubnetDetail struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ServiceTypes    string `json:"service_types"`
	Description     string `json:"description"`
	EnableDHCP      bool   `json:"enable_dhcp"`
	SegmentID       string `json:"segment_id"`
	NetworkID       string `json:"network_id"`
	CreatedAt       string `json:"created_at"`
	Tags            string `json:"tags"`
	DNSNameServers  string `json:"dns_nameservers"`
	UpdatedAt       string `json:"updated_at"`
	IPv6RAMode      string `json:"ipv6_ra_mode"`
	AllocationPools string `json:"allocation_pools"`
	GatewayIP       string `json:"gateway_ip"`
	RevisionNumber  int    `json:"revision_number"`
	IPv6AddressMode string `json:"ipv6_address_mode"`
	IPVersion       int    `json:"ip_version"`
	HostRoutes      string `json:"host_routes"`
	CIDR            string `json:"cidr"`
	ProjectID       string `json:"project_id"`
	SubnetPoolID    string `json:"subnetpool_id"`
}

//Router is used with 'openstack router' commands.
// In openstack  router is virtually created to connect different subnets
//  and possible to external networks.
type Router struct {
	Name, ID, Status, State, HA, Project, Distributed string
}

//RouterDetail lists more info per router
type RouterDetail struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	ExternalGatewayInfo   string `json:"external_gateway_info"`
	Status                string `json:"status"`
	AvailabilityZoneHints string `json:"availability_zone_hints"`
	AvailabilityZones     string `json:"availability_zones"`
	Description           string `json:"description"`
	AdminStateUp          string `json:"admin_state_up"`
	CreatedAt             string `json:"created_at"`
	Tags                  string `json:"tags"`
	Distributed           string `json:"distributed"`
	UpdatedAt             string `json:"updated_at"`
	InterfacesInfo        string `json:"interfaces_info"`
	ProjectID             string `json:"project_id"`
	FlavorID              string `json:"flavor_id"`
	RevisionNumber        int    `json:"revision_number"`
	Routes                string `json:"routes"`
	HA                    string `json:"ha"`
}

//ExternalGateway details the info inside RouterDetail. The ExternalGatewayInfo is
// a string, which has to be double unmarshal'ed
type ExternalGateway struct {
	NetworkID        string            `json:"network_id"` //subnet of external net
	EnableSNAT       bool              `json:"enable_snat"`
	ExternalFixedIPs []ExternalFixedIP `json:"external_fixed_ips"` //gateway between extnet and privnet
}

//ExternalFixedIP similarly needs to be double unmarshalled as part of the above
type ExternalFixedIP struct {
	SubnetID  string `json:"subnet_id"`
	IPAddress string `json:"ip_address"`
}

//RouterInterface also needs to be used for double unmarshal
type RouterInterface struct {
	SubnetID  string `json:"subnet_id"`  //attached privnet
	IPAddress string `json:"ip_address"` //router for the privnet side on the subnet CIDR, usually X.X.X.1  but should really confirm by reading this
	PortID    string `json:"port_id"`
}

// "Is Public" field  is missing in 'Router'

//GetLimits is used to retrieve tenant level platform stats
func GetLimits() ([]Limit, error) {
	//err := sh.Command("openstack", "limits", "show", "--absolute", "-f", "json", sh.Dir("/tmp")).WriteStdout("os-out.txt")
	out, err := sh.Command("openstack", "limits", "show", "--absolute", "-f", "json", sh.Dir("/tmp")).Output()
	if err != nil {
		err = fmt.Errorf("cannot get limits from openstack, %v", err)
		return nil, err
	}

	var limits []Limit
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.Debugln("limits", limits)
	return limits, nil
}

//ListServers returns list of servers, KVM instances, running on the system
func ListServers() ([]Server, error) {
	out, err := sh.Command("openstack", "server", "list", "-f", "json").Output()
	if err != nil {
		err = fmt.Errorf("cannot get server list, %v", err)
		return nil, err
	}

	var servers []Server
	err = json.Unmarshal(out, &servers)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.Debugln("servers", servers)
	return servers, nil
}

//ListImages lists avilable images in glance
func ListImages() ([]Image, error) {
	out, err := sh.Command("openstack", "image", "list", "-f", "json").Output()
	if err != nil {
		err = fmt.Errorf("cannot get image list, %v", err)
		return nil, err
	}

	var images []Image
	err = json.Unmarshal(out, &images)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.Debugln("images", images)
	return images, nil
}

//ListNetworks lists networks known to the platform. Some created by the operator, some by users.
func ListNetworks() ([]Network, error) {
	out, err := sh.Command("openstack", "network", "list", "-f", "json").Output()
	if err != nil {
		err = fmt.Errorf("cannot get network list, %v", err)
		return nil, err
	}

	var networks []Network
	err = json.Unmarshal(out, &networks)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.Debugln("networks", networks)
	return networks, nil
}

//ListFlavors lists flavors known to the platform. These vary. On Buckhorn cloudlet the are m4. prefixed.
func ListFlavors() ([]Flavor, error) {
	out, err := sh.Command("openstack", "flavor", "list", "-f", "json").Output()
	if err != nil {
		err = fmt.Errorf("cannot get flavor list, %v", err)
		return nil, err
	}

	var flavors []Flavor
	err = json.Unmarshal(out, &flavors)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.Debugln("flavors", flavors)
	return flavors, nil
}

//CreateServer instantiates a new server instance, which is a KVM instance based on a qcow2 image from glance
func CreateServer(opts *ServerOpt) error {
	args := []string{
		"server", "create",
		"--config-drive", "true", //XXX always
		"--image", opts.Image, "--flavor", opts.Flavor,
		"--user-data", opts.UserData,
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

	log.Debugln("openstack create server")
	log.Debugln(iargs...)
	out, err := sh.Command("openstack", iargs...).Output()
	if err != nil {
		err = fmt.Errorf("cannot create server, %v, '%s'", err, out)
		return err
	}

	return nil
}

// GetServerDetails returns details of the KVM instance
func GetServerDetails(name string) (*ServerDetail, error) {
	active := false
	srvDetail := &ServerDetail{}
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
		log.Debugln("wait for server to become ACTIVE", srvDetail)
		time.Sleep(30 * time.Second)
	}
	if !active {
		return nil, fmt.Errorf("while getting server detail, waited but server %s is too slow getting to active state", name)
	}

	log.Debugln(srvDetail)
	return srvDetail, nil
}

//DeleteServer destroys a KVM instance
//  sometimes it is not possible to destroy. Like most things in Openstack, try again.
func DeleteServer(id string) error {
	log.Debugln("deleting server", id)
	out, err := sh.Command("openstack", "server", "delete", id).Output()
	if err != nil {
		err = fmt.Errorf("can't delete server %s, %s, %v", id, out, err)
		return err
	}
	return nil
}

// CreateNetwork creates a network with a name.
func CreateNetwork(name string) error {
	log.Debugln("creating network", name)
	out, err := sh.Command("openstack", "network", "create", name).Output()
	if err != nil {
		err = fmt.Errorf("can't create network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//DeleteNetwork destroys a named network
//  Sometimes it will fail. Openstack will refuse if there are resources attached.
func DeleteNetwork(name string) error {
	log.Debugln("deleting network", name)
	out, err := sh.Command("openstack", "network", "delete", name).Output()
	if err != nil {
		err = fmt.Errorf("can't delete network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//NeutronErrorDetail holds neturon error
type NeutronErrorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Detail  string `json:"detail"`
}

//NeutronErrorType container for the NeutronErrorDetail
type NeutronErrorType struct {
	NeutronError NeutronErrorDetail
}

//CreateSubnet creates a subnet within a network. A subnet is assigned ranges. Optionally DHCP can be enabled.
func CreateSubnet(netRange, networkName, gatewayAddr, subnetName string, dhcpEnable bool) error {
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
				sd, serr := GetSubnetDetail(subnetName)
				if serr != nil {
					return fmt.Errorf("cannot get subnet detail for %s, while fixing overlap error, %v", subnetName, serr)
				}
				log.Debugln("create subnet, existing subnet detail", sd)

				//XXX do more validation

				log.Warningf("create subnet, reusing existing subnet, error was %s, %v", out, err)
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
	log.Debugln("deleting subnet", subnetName)
	out, err := sh.Command("openstack", "subnet", "delete", subnetName).Output()
	if err != nil {
		err = fmt.Errorf("can't delete subnet %s, %s, %v", subnetName, out, err)
		return err
	}
	return nil
}

//CreateRouter creates new router. A router can be attached to network and subnets.
func CreateRouter(routerName string) error {
	log.Debugln("creating router", routerName)
	out, err := sh.Command("openstack", "router", "create", routerName).Output()
	if err != nil {
		err = fmt.Errorf("can't create router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//DeleteRouter removes the named router. The router needs to not be in use at the time of deletion.
func DeleteRouter(routerName string) error {
	log.Debugln("deleting router", routerName)
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
func SetRouter(routerName, networkName string) error {
	log.Debugln("setting router to network", routerName, networkName)
	out, err := sh.Command("openstack", "router", "set", routerName, "--external-gateway", networkName).Output()
	if err != nil {
		err = fmt.Errorf("can't set router %s to %s, %s, %v", routerName, networkName, out, err)
		return err
	}
	return nil
}

//AddRouterSubnet will connect subnet to another network, possibly external, via a router
func AddRouterSubnet(routerName, subnetName string) error {
	log.Debugln("adding router to subnet", routerName, subnetName)
	out, err := sh.Command("openstack", "router", "add", "subnet", routerName, subnetName).Output()
	if err != nil {
		err = fmt.Errorf("can't add router %s to subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//RemoveRouterSubnet is useful to remove the router from the subnet before deletion. Otherwise subnet cannot
//  be deleted.
func RemoveRouterSubnet(routerName, subnetName string) error {
	log.Debugln("removing router from subnet", routerName, subnetName)
	out, err := sh.Command("openstack", "router", "remove", "subnet", routerName, subnetName).Output()
	if err != nil {
		err = fmt.Errorf("can't remove router %s from subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//ListSubnets returns a list of subnets available
func ListSubnets(netName string) ([]Subnet, error) {
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

	subnets := []Subnet{}
	err = json.Unmarshal(out, &subnets)
	if err != nil {
		err = fmt.Errorf("can't unmarshal subnets, %v", err)
		return nil, err
	}

	log.Debugln("subnets", subnets)
	return subnets, nil
}

//ListRouters returns a list of routers available
func ListRouters() ([]Router, error) {
	out, err := sh.Command("openstack", "router", "list", "-f", "json").Output()
	if err != nil {
		err = fmt.Errorf("can't get a list of routers, %s, %v", out, err)
		return nil, err
	}

	routers := []Router{}

	err = json.Unmarshal(out, &routers)
	if err != nil {
		err = fmt.Errorf("can't unmarshal routers, %v", err)
		return nil, err
	}

	log.Debugln("routers", routers)
	return routers, nil
}

//GetRouterDetail returns details per router
func GetRouterDetail(routerName string) (*RouterDetail, error) {
	out, err := sh.Command("openstack", "router", "show", "-f", "json", routerName).Output()
	if err != nil {
		err = fmt.Errorf("can't get router details for %s, %s, %v", routerName, out, err)
		return nil, err
	}

	routerDetail := &RouterDetail{}

	err = json.Unmarshal(out, routerDetail)
	if err != nil {
		err = fmt.Errorf("can't unmarshal router detail, %v", err)
		return nil, err
	}

	log.Debugln("router detail", routerDetail)
	return routerDetail, nil
}

//CreateImage snapshots running service into a qcow2 image
func CreateImage(serverName, imageName string) error {
	log.Debugln("creating image", serverName, imageName)
	out, err := sh.Command("openstack", "image", "create", serverName, "--name", imageName).Output()
	if err != nil {
		err = fmt.Errorf("can't create image from %s into %s, %s, %v", serverName, imageName, out, err)
		return err
	}

	return nil
}

//SaveImage takes the image name available in glance, as a result of for example the above create image.
// It will then save that into a local file. The image transfer happens from glance into your own laptop
// or whatever.
// This can take a while, transferring all the data.
func SaveImage(saveName, imageName string) error {
	log.Debugln("saving image", saveName, imageName)
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
func DeleteImage(imageName string) error {
	log.Debugln("deleting image", imageName)
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
func GetSubnetDetail(subnetName string) (*SubnetDetail, error) {
	out, err := sh.Command("openstack", "subnet", "show", "-f", "json", subnetName).Output()
	if err != nil {
		err = fmt.Errorf("can't get subnet details for %s, %s, %v", subnetName, out, err)
		return nil, err
	}
	subnetDetail := &SubnetDetail{}
	err = json.Unmarshal(out, subnetDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal subnet detail, %v", err)
	}

	log.Debugln("subnet detail", subnetDetail)
	return subnetDetail, nil
}

//GetNetworkDetail returns details about a network.  It is used, for example, by GetExternalGateway.
func GetNetworkDetail(networkName string) (*NetworkDetail, error) {
	out, err := sh.Command("openstack", "network", "show", "-f", "json", networkName).Output()
	if err != nil {
		err = fmt.Errorf("can't get details for network %s, %s, %v", networkName, out, err)
		return nil, err
	}
	networkDetail := &NetworkDetail{}
	err = json.Unmarshal(out, networkDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal network detail, %v", err)
	}

	log.Debugln("network detail", networkDetail)
	return networkDetail, nil
}

//GetExternalGateway retrieves Gateway IP from the external network information. It first gets external
//  network information. Using that it further gets subnet information. Inside that subnet information
//  there should be gateway IP if the network is set up correctly.
// Not to be confused with GetRouterDetailExternalGateway.
func GetExternalGateway(extNetName string) (string, error) {
	nd, err := GetNetworkDetail(extNetName)
	if err != nil {
		return "", fmt.Errorf("can't get details for external network %s, %v", extNetName, err)
	}

	if nd.Status != "ACTIVE" {
		return "", fmt.Errorf("network %s is not active, status %s", extNetName, nd.Status)
	}

	if nd.AdminStateUp != "UP" {
		return "", fmt.Errorf("network %s is not admin-state set to up", extNetName)
	}

	subnets := strings.Split(nd.Subnets, ",")
	//XXX beware of extra spaces
	if len(subnets) < 1 {
		return "", fmt.Errorf("no subnets for %s", extNetName)
	}

	//XXX just use first subnet -- may not work in all cases, but there is no tagging done rightly yet

	sd, err := GetSubnetDetail(subnets[0])
	if err != nil {
		return "", fmt.Errorf("cannot get details for subnet %s, %v", subnets[0], err)
	}

	//TODO check status of subnet

	if sd.GatewayIP == "" {
		return "", fmt.Errorf("cannot get external network's gateway IP")
	}
	log.Debugln("gatewayIP", sd)

	return sd.GatewayIP, nil
}

//GetNextSubnetRange will find the CIDR for the next range of subnet that can be created. For example,
// if the subnet detail we get has 10.101.101.0/24 then the next one can be 10.101.102.0/24
func GetNextSubnetRange(subnetName string) (string, error) {
	sd, err := GetSubnetDetail(subnetName)
	if err != nil {
		return "", err
	}
	if sd.CIDR == "" {
		return "", fmt.Errorf("missing CIDR in subnet %s", subnetName)
	}
	_, ipv4Net, err := net.ParseCIDR(sd.CIDR)
	if err != nil {
		return "", fmt.Errorf("can't parse CIDR %s, %v", sd.CIDR, err)
	}

	i := strings.Index(sd.CIDR, "/")
	suffix := sd.CIDR[i:]
	v4 := ipv4Net.IP.To4()
	ipnew := net.IPv4(v4[0], v4[1], v4[2]+1, v4[3])

	log.Debugln("next subnet range", ipnew, suffix)
	return ipnew.String() + suffix, nil
}

//GetRouterDetailExternalGateway is different than GetExternalGateway.  This function gets
// the gateway interface in the subnet within external network.  This is
// accessible from private networks to route packets to the external network.
// The GetExternalGateway gets the gateway for the outside network.   This is
// for the packets to be routed out to the external network, i.e. internet.
func GetRouterDetailExternalGateway(rd *RouterDetail) (*ExternalGateway, error) {
	if rd.ExternalGatewayInfo == "" {
		return nil, fmt.Errorf("empty external gateway info")
	}

	externalGateway := &ExternalGateway{}

	err := json.Unmarshal([]byte(rd.ExternalGatewayInfo), externalGateway)
	if err != nil {
		return nil, fmt.Errorf("can't get unmarshal external gateway info, %v", err)
	}

	log.Debugln("external gateway", externalGateway)
	return externalGateway, nil
}

// GetRouterDetailInterfaces gets the list of interfaces on the router. For example, each private
// subnet connected to the router will be listed here with own interface definition.
func GetRouterDetailInterfaces(rd *RouterDetail) ([]RouterInterface, error) {
	if rd.InterfacesInfo == "" {
		return nil, fmt.Errorf("missing interfaces info in router details")
	}

	interfaces := []RouterInterface{}

	err := json.Unmarshal([]byte(rd.InterfacesInfo), &interfaces)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal router detail interfaces")
	}

	log.Debugln("interfaces", interfaces)
	return interfaces, nil
}

//SetServerProperty sets properties for the server
func SetServerProperty(name, property string) error {
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
	log.Debugln("set server property", name, property)
	return nil
}
