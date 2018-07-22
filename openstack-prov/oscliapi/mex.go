package oscli

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// These are platform specific custom vars

var eMEXLargeImageName = os.Getenv("MEX_LARGE_IMAGE") // "mobiledgex-16.04-2"
var eMEXLargeFlavor = os.Getenv("MEX_LARGE_FLAVOR")   // "m4.large"
var eMEXUserData = os.Getenv("MEX_USERDATA")          // "/home/bob/userdata.txt"
var eMEXDir = os.Getenv("MEX_DIR")

var defaultImage = "mobiledgex-16.04-2"
var defaultFlavor = "m4.large"

//For netspec components
//  netType,netName,netCIDR,netOptions
const (
	NET_TYPE = 0
	NET_NAME = 1
	NET_CIDR = 2
	NET_OPT  = 3
)

type NetSpecInfo struct {
	Kind, Name, CIDR, Options string
	Extra                     []string
}

func init() {
	if eMEXLargeImageName == "" {
		eMEXLargeImageName = defaultImage
	}

	if eMEXLargeFlavor == "" {
		eMEXLargeFlavor = defaultFlavor
	}

	hm := os.Getenv("HOME")

	if eMEXDir == "" {
		eMEXDir = hm + "/.mobiledgex"
	}

	if eMEXUserData == "" {
		eMEXUserData = eMEXDir + "/userdata.txt"
	}
}

//CreateFlavorMEXVM creates basic KVM for mobiledgex applications
//  with proper initial bootstrap scripts installed on the base image that understands
//  various properties such as role, topology of private net, gateway IP, etc.
// Roles can be any string but special ones are k8s-master and k8s-node.
//  To avoid running bootstrap setup for creating kubernets cluster, set skipk8s to true.
// For more detailed information please read `mobiledgex-init.sh`
func CreateFlavorMEXVM(name, image, flavor, netID, userdata, role, edgeproxy, skipk8s, k8smaster, privatenet, privaterouter, tags, tenant string) error {
	if name == "" {
		return fmt.Errorf("name required")
	}

	if netID == "" {
		return fmt.Errorf("net-id required")
	}

	if image == "" {
		image = eMEXLargeImageName
	}
	if flavor == "" {
		flavor = eMEXLargeFlavor
	}

	if userdata == "" {
		userdata = eMEXUserData
	}

	opts := &ServerOpt{
		Name:     name,
		Image:    image,
		Flavor:   flavor,
		UserData: userdata,
		NetIDs:   []string{netID}, //XXX more than one?
	}

	props := []string{}

	//edgeproxy should be pointing to external gateway IP when running a agent-proxy node.
	//  agent proxy node has direct connection to external network. The gateway of that
	//  network is edgeproxy setting.
	//edgeproxy should be pointing to internal gateway IP when running on private network.
	//  Typically like 10.101.101.1

	props = append(props, "edgeproxy="+edgeproxy)
	props = append(props, "role="+role)
	props = append(props, "skipk8s="+skipk8s)
	props = append(props, "k8smaster="+k8smaster)

	//privatenet, privaterouter are used when in agent-proxy mode. It deals with external
	//  and internet network.  Normal k8s nodes do not look at these.
	//privaterouter should be pointing to the router instance's external network address
	//  which is reachable from internal network.
	props = append(props, "privatenet="+privatenet)
	props = append(props, "privaterouter="+privaterouter)
	props = append(props, "tags="+tags)
	props = append(props, "tenant="+tenant)

	opts.Properties = props

	err := CreateServer(opts)
	if err != nil {
		return fmt.Errorf("can't create server %v, %v", opts, err)
	}

	return nil
}

//CreateMEXKVM is easier way to create a MEX app capable KVM
//  role can be k8s-master, k8s-node, or something else
func CreateMEXKVM(name, role, netSpec, tags, tenant string, id int) error {
	mexRouter := GetMEXExternalRouter()
	netID := GetMEXExternalNetwork() //do we really want to default to ext?
	skipk8s := "yes"
	masterIP := ""
	privRouterIP := ""
	privNet := ""
	edgeProxy := ""

	var err error

	//if role == "mex-agent-node" docker will be installed automatically

	if netSpec == "" {
		return fmt.Errorf("empty netspec")
	}

	ni, err := ParseNetSpec(netSpec)
	if err != nil {
		return fmt.Errorf("can't parse netSpec %s, %v", netSpec, err)
	}

	if role == "k8s-master" || role == "k8s-node" {
		skipk8s = "no"
		// XXX if there was nothing set up on the cloudlet, we may have to ask the operator
		//  the initial external network which has connection to internet.
		//  And add at least one network for MEX use.
		//  And add at least one subnet inside that network.
		//  And add a router for MEX use.
		//  And set that router to external network created by the operator.
		//  And add that router to the subnet.
		// However, we need to normally operate with these things already setup.
		//  So the code here assumes this.

		// XXX do not create a new network, use existing MEXNet
		//nn := "net-" + name
		//err := CreateNetwork(nn)
		//if err != nil {
		//	return fmt.Errorf("can't create network %s, %v", nn, err)
		//}

		//err = CreateRouter("router-"+name)
		//err = SetRouter("router-"+name, "net-"+name)

		// We assume router is set to external network. So just attach a new port / subnet to this router

		if ni.CIDR == "" {
			return fmt.Errorf("missing CIDR spec in %v", ni)
		}

		if ni.Name != GetMEXNetwork() { //XXX for now
			return fmt.Errorf("netspec net name %s not equal to default MEX net %s", ni.Name, GetMEXNetwork())
		}

		//XXX openstack bug - subnet does not take tags but description field can be used to tag stuff
		//   Use tag as part of name

		sn := ni.Name + "-subnet-" + tags
		snd, err := GetSubnetDetail(sn)
		if err != nil {
			if role == "k8s-node" {
				return fmt.Errorf("subnet %s does not exist, %v", sn, err)
			}
			// k8s-master will create one
		}

		if role == "k8s-master" && snd == nil {
			sits := strings.Split(ni.CIDR, "/")
			if len(sits) < 2 {
				return fmt.Errorf("invalid CIDR , no net mask")
			}

			its := strings.Split(sits[0], ".")

			if len(its) != 4 {
				return fmt.Errorf("invalid CIDR spec %v", ni)
			}
			if strings.Index(sits[0], "X") < 0 {
				return fmt.Errorf("missing marker in CIDR spec %v", ni)
			}
			octno := 0
			for i, it := range its {
				if it == "X" {
					octno = i
				}
			}
			if octno < 0 || octno > 3 {
				return fmt.Errorf("net CIDR, cannot find marker")
			}

			if octno == 3 {
				return fmt.Errorf("net CIDR, danger, too small")
			}

			// we want octno to be 2 really
			if octno != 2 {
				return fmt.Errorf("net CIDR, we want octno to be 2 for now")
			}

			sns, err := ListSubnets(ni.Name)
			if err != nil {
				return fmt.Errorf("can't get list of subnets for %s, %v", ni.Name, err)
			}

			//XXX because controller does not want to have any idea about existing network conditions
			// we have to figure out the details the best way we can, even though it is not
			// always possible to do so.  Ideally controller should have some ideas about
			// what can be reasonably done. Instead of flying blindly, it should coordinate
			// with CRM to do what makes the most sense as with any other resources -- CPU, Mem, etc.
			// But controller design is only looking at CPU, mem, max project limits only.

			maxoct := 0
			for _, s := range sns {
				// TODO validate the prefix of the subnet name based on net-name
				//   to make sure it belongs here
				sna := s.Subnet
				ipa, _, err := net.ParseCIDR(sna)
				if err != nil {
					return fmt.Errorf("while iterating subnets, can't parse %s, %v", sna, err)
				}

				v4a := ipa.To4()
				iv := int(v4a[octno])

				if iv > maxoct {
					maxoct = iv
				}
			}
			id = id + 1
			// gateway is at X.X.X.1
			if id > 99 {
				return fmt.Errorf("k8s-master id is too big")
			}
			maxoct++
			ni.CIDR = fmt.Sprintf("%s.%s.%d.%d/%s", its[0], its[1], maxoct, id, sits[1])

		} else {
			if snd == nil {
				// should not happen
				return fmt.Errorf("subnet %s not found", sn)
			}

			id = id + 100
			// worker nodes start at 100+id.
			// there may be many masters... allow for upto 100!

			//leave some space at end
			if id > 250 {
				return fmt.Errorf("k8s-node id is too big")
			}
			sits := strings.Split(ni.CIDR, "/")
			if len(sits) < 2 {
				return fmt.Errorf("invalid subnet CIDR %s, no net mask", snd.CIDR)
			}
			ipa, _, err := net.ParseCIDR(snd.CIDR)
			if err != nil {
				return fmt.Errorf("can't parse subnet CIDR %s, %v", snd.CIDR, err)
			}

			v4a := ipa.To4()
			ni.CIDR = fmt.Sprintf("%d.%d.%d.%d/%s", v4a[0], v4a[1], v4a[2], id, sits[1])
			// we can have up to 150 nodes of workers per subnet.
			// change these values as needed.
		}

		ipv4Addr, _, err := net.ParseCIDR(ni.CIDR)
		if err != nil {
			return fmt.Errorf("can't parse %s, %v", ni.CIDR, err)
		}
		v4 := ipv4Addr.To4()

		//gateway always at X.X.X.1
		gatewayIP := net.IPv4(v4[0], v4[1], v4[2], byte(1))

		edgeProxy = gatewayIP.String()

		ipaddr := net.IPv4(v4[0], v4[1], v4[2], v4[3])
		if role == "k8s-master" {
			err = CreateSubnet(ni.CIDR, GetMEXNetwork(), edgeProxy, sn, false)
			if err != nil {
				return err
			}

			//TODO: consider adding tags to subnet

			err = AddRouterSubnet(mexRouter, sn)
			if err != nil {
				return fmt.Errorf("cannot add router %s to subnet %s, %v", mexRouter, sn, err)
			}
		}
		//XXX need to tell agent to add route for the cidr

		//+1 because gatway is at .1
		//master node num is 1
		//so, master node will always have .2
		netID = GetMEXNetwork() + ",v4-fixed-ip=" + ipaddr.String()

		//XXX master always at X.X.X.2
		ipaddr = net.IPv4(v4[0], v4[1], v4[2], byte(2))
		masterIP = ipaddr.String()
	} else {
		// NOT k8s case
		// for now just agent stuff.

		edgeProxy, err = GetExternalGateway(netID)
		if err != nil {
			return fmt.Errorf("can't get external gateway for %s, %v", netID, err)
		}

		rd, err := GetRouterDetail(mexRouter)
		if err != nil {
			return fmt.Errorf("can't get router detail for %s, %v", mexRouter, err)
		}

		reg, err := GetRouterDetailExternalGateway(rd)
		if err != nil {
			return fmt.Errorf("can't get router detail external gateway, %v", err)
		}
		if len(reg.ExternalFixedIPs) < 1 {
			return fmt.Errorf("can't get external fixed ips list from router detail external gateway")
		}
		fip := reg.ExternalFixedIPs[0]

		// router IP for the private network to the external side, which
		//  also knows about the private side. Only needed for agent gw node.
		privRouterIP = fip.IPAddress

		//XXX CIDR is not real, but a pattern like 10.101.X.X.  marginally useful for now. may change later.
		//_, _, err = net.ParseCIDR(ni.CIDR)
		//if err != nil {
		//	return fmt.Errorf("can't parse CIDR %v, %v", ni, err)
		//}

		//XXX ni.Options DHCP case should trigger registration of the DNS name based on dynamic IP from DHCP server.
		//   Especially on cloudlets like GDDT where they force DHCP on external network.

		//privNet = ni.CIDR
		privNet = ""
		//XXX empty privNet  avoids adding initial route to the privRouterIP. privRouterIP is still needed.
		//   for adding routes later.
	}
	err = CreateFlavorMEXVM(name,
		eMEXLargeImageName,
		eMEXLargeFlavor,
		netID, // either external-net or internal-net,v4-fixed-ip=X.X.X.X
		eMEXUserData,
		role, // k8s-master,k8s-node,something else
		edgeProxy,
		skipk8s,  // if yes, skip
		masterIP, // relevant when forming k8s cluster
		privNet,
		privRouterIP,
		tags,
		tenant,
	)

	if err != nil {
		return err
	}

	return nil
}

//DestroyMEXKVM deletes the MEX KVM instance. If server instance is k8s-master,
//  first remove router from subnet which was created for it. Then remove subnet before
//  deleting server KVM instance.
func DestroyMEXKVM(name, role string) error {
	err := DeleteServer(name)
	if err != nil {
		return fmt.Errorf("can't delete %s, %v", name, err)
	}

	if role == "k8s-master" {
		sn := "subnet-" + name
		rn := GetMEXExternalRouter()

		err := RemoveRouterSubnet(rn, sn)
		if err != nil {
			return fmt.Errorf("can't remove router %s from subnet %s, %v", rn, sn, err)
		}

		//XXX This may not work until all nodes are removed, since
		//   IP addresses are allocated out of this subnet
		//   All nodes should be deleted first.
		err = DeleteSubnet(sn)
		if err != nil {
			return fmt.Errorf("can't delete subnet %s, %v", sn, err)
		}
	}

	return nil
}

func ParseNetSpec(netSpec string) (*NetSpecInfo, error) {
	ni := &NetSpecInfo{}
	if netSpec == "" {
		return nil, fmt.Errorf("empty netspec")
	}

	items := strings.Split(netSpec, ",")

	if len(items) < 3 {
		return nil, fmt.Errorf("malformed net spec, insufficient items")
	}

	ni.Kind = items[NET_TYPE]
	ni.Name = items[NET_NAME]
	ni.CIDR = items[NET_CIDR]

	if len(items) == 4 {
		ni.Options = items[NET_OPT]
	}
	if len(items) > 5 {
		ni.Extra = items[NET_OPT+1:]
	}

	switch items[NET_TYPE] {
	case "priv-subnet":
		return ni, nil
	case "external-ip":
		return ni, nil
	default:
	}
	return nil, fmt.Errorf("unsupported netspec type")
}
