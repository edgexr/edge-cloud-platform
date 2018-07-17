package oscli

import (
	"fmt"
	"net"
	"os"
)

// These are platform specific custom vars

var eMEXLargeImageName = os.Getenv("MEX_LARGE_IMAGE") // "mobiledgex-16.04-2"
var eMEXLargeFlavor = os.Getenv("MEX_LARGE_FLAVOR")   // "m4.large"
var eMEXUserData = os.Getenv("MEX_USERDATA")          // "/home/bob/userdata.txt"

var defaultImage = "mobiledgex-16.04-2"
var defaultFlavor = "m4.large"

func init() {
	if eMEXLargeImageName == "" {
		eMEXLargeImageName = defaultImage
	}

	if eMEXLargeFlavor == "" {
		eMEXLargeFlavor = defaultFlavor
	}

	if eMEXUserData == "" {
		hm := os.Getenv("HOME")
		eMEXUserData = hm + "/userdata.txt"
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
func CreateMEXKVM(name, role, cidr, tags, tenant string) error {
	mexRouter := GetMEXExternalRouter()
	netID := GetMEXExternalNetwork() //do we really want to default to ext?
	skipk8s := "yes"
	masterIP := ""
	privRouterIP := ""
	privNet := ""
	edgeProxy := ""

	var err error

	//if role == "mex-agent-node" docker will be installed automatically

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

		ipv4Addr, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("can't parse %s, %v", cidr, err)
		}
		v4 := ipv4Addr.To4()

		//gateway always at X.X.X.1
		gatewayIP := net.IPv4(v4[0], v4[1], v4[2], byte(1))

		sn := "subnet-" + name
		edgeProxy = gatewayIP.String()

		ipaddr := net.IPv4(v4[0], v4[1], v4[2], v4[3])
		if role == "k8s-master" {
			err = CreateSubnet(cidr, GetMEXNetwork(), edgeProxy, sn, false)
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
		privNet = cidr
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
