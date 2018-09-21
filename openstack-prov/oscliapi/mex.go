package oscli

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

// These are platform specific custom vars

var eMEXLargeImageName = os.Getenv("MEX_LARGE_IMAGE") // "mobiledgex-16.04-2"
var eMEXLargeFlavor = os.Getenv("MEX_LARGE_FLAVOR")   // "m4.large"
var eMEXUserData = os.Getenv("MEX_USERDATA")          // "/home/bob/userdata.txt"
var eMEXDir = os.Getenv("MEX_DIR")
var eMEXSubnetSeed = 100  // XXX
var eMEXSubnetLimit = 250 // XXX
var defaultImage = "mobiledgex-16.04-2"
var defaultFlavor = "m4.large"

const (
	k8smasterRole = "k8s-master"
	k8snodeRole   = "k8s-node"
)

//For netspec components
//  netType,netName,netCIDR,netOptions
const (
	NetTypeVal = 0
	NetNameVal = 1
	NetCIDRVal = 2
	NetOptVal  = 3
)

//NetSpecInfo has basic layout for netspec
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
	log.DebugLog(log.DebugLevelMexos, "mex init environment", "MEX_LARGE_IMAGE", eMEXLargeImageName, "MEX_LARGE_FLAVOR",
		eMEXLargeFlavor, "MEX_USERDATA", eMEXUserData, "MEX_DIR", eMEXDir)
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
	sd, err := GetServerDetails(name)
	if err == nil {
		log.DebugLog(log.DebugLevelMexos, "warning, server already exists", "name", sd.Name, "server detail", sd)
		return nil
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
	log.DebugLog(log.DebugLevelMexos, "create flavor MEX KVM", "server opts", opts)
	err = CreateServer(opts)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error creating flavor MEX KVM", "server opts", opts)
		return fmt.Errorf("can't create server, opts %v, %v", opts, err)
	}
	return nil
}

//CreateMEXKVM is easier way to create a MEX app capable KVM
//  role can be k8s-master, k8s-node, or something else
func CreateMEXKVM(name, role, netSpec, tags, tenant string, id int) error {
	log.DebugLog(log.DebugLevelMexos, "createMEXKVM", "name", name, "role", role, "netSpec", netSpec,
		"tags", tags, "tenant", tenant, "id", id)
	mexRouter := GetMEXExternalRouter()
	netID := GetMEXExternalNetwork() //do we really want to default to ext?
	skipk8s := "yes"
	var masterIP, privRouterIP, privNet, edgeProxy string
	var err error
	//if role == "mex-agent-node" docker will be installed automatically
	if netSpec == "" {
		return fmt.Errorf("empty netspec")
	}
	ni, err := ParseNetSpec(netSpec)
	if err != nil {
		return fmt.Errorf("can't parse netSpec %s, %v", netSpec, err)
	}
	if role == k8smasterRole || role == k8snodeRole {
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
		snd, snderr := GetSubnetDetail(sn)
		if snderr != nil {
			if role == k8snodeRole {
				return fmt.Errorf("subnet %s does not exist, %v", sn, snderr)
			}
			// k8s-master will create one
		}
		if snd == nil {
			log.DebugLog(log.DebugLevelMexos, "warning, subnet does not exist, will create one, as k8s master", "subnet name", sn)
		}
		if role == k8smasterRole {
			sits := strings.Split(ni.CIDR, "/")
			if len(sits) < 2 {
				return fmt.Errorf("invalid CIDR , no net mask")
			}
			its := strings.Split(sits[0], ".")
			if len(its) != 4 {
				return fmt.Errorf("invalid CIDR spec %v", ni)
			}
			if !strings.Contains(sits[0], "X") {
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
			sns, snserr := ListSubnets(ni.Name)
			if snserr != nil {
				return fmt.Errorf("can't get list of subnets for %s, %v", ni.Name, snserr)
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
				ipa, _, ipaerr := net.ParseCIDR(sna)
				if ipaerr != nil {
					return fmt.Errorf("while iterating subnets, can't parse %s, %v", sna, ipaerr)
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
			if snd == nil {
				log.DebugLog(log.DebugLevelMexos, "no subnet for this cluster exists, ok")
				maxoct++
				ni.CIDR = fmt.Sprintf("%s.%s.%d.%d/%s", its[0], its[1], maxoct, id, sits[1])
			} else {
				log.DebugLog(log.DebugLevelMexos, "subnet for this cluster existed", "subnet detail", snd)
				ni.CIDR = snd.CIDR
			}
			log.DebugLog(log.DebugLevelMexos, "allocated CIDR", "cidr", ni.CIDR)
		} else {
			if snd == nil {
				log.DebugLog(log.DebugLevelMexos, "error, subnet not found; this should not happen!", "name", sn)
				// should not happen
				return fmt.Errorf("subnet %s not found", sn)
			}
			id = id + eMEXSubnetSeed
			log.DebugLog(log.DebugLevelMexos, "starting third octet at", "id", id)
			// worker nodes start at 100+id.
			// there may be many masters... allow for upto 100!
			//leave some space at end
			if id > eMEXSubnetLimit {
				log.DebugLog(log.DebugLevelMexos, "error k8s-node is is too big", "id", id)
				return fmt.Errorf("k8s-node id is too big")
			}
			sits := strings.Split(ni.CIDR, "/")
			if len(sits) < 2 {
				return fmt.Errorf("invalid subnet CIDR %s, no net mask", snd.CIDR)
			}
			ipa, _, ipaerr := net.ParseCIDR(snd.CIDR)
			if ipaerr != nil {
				return fmt.Errorf("can't parse subnet CIDR %s, %v", snd.CIDR, ipaerr)
			}
			v4a := ipa.To4()
			ni.CIDR = fmt.Sprintf("%d.%d.%d.%d/%s", v4a[0], v4a[1], v4a[2], id, sits[1])
			// we can have up to 150 nodes of workers per subnet.
			// change these values as needed.
			sl, err := ListSubnets(ni.Name)
			if err != nil {
				return fmt.Errorf("can't get a list of subnets, %v", err)
			}
			for _, sn := range sl {
				sd, err := GetSubnetDetail(sn.ID)
				if err != nil {
					return fmt.Errorf("can't get subnet detail, %s, %v", sn.Name, err)
				}
				if sd.CIDR == ni.CIDR {
					log.DebugLog(log.DebugLevelMexos, "subnet exists with the same CIDR, find another range", "CIDR", sd.CIDR)
					cidr, err := getNewSubnetRange(id, v4a, sits, sl)
					if err != nil {
						return fmt.Errorf("failed to get a new subnet range, %v", err)
					}
					ni.CIDR = *cidr
				}
			}
		}
		log.DebugLog(log.DebugLevelMexos, "computed CIDR", "ni", ni, "role", role)
		ipv4Addr, _, iperr := net.ParseCIDR(ni.CIDR)
		if iperr != nil {
			return fmt.Errorf("can't parse %s, %v", ni.CIDR, iperr)
		}
		v4 := ipv4Addr.To4()
		//gateway always at X.X.X.1
		gatewayIP := net.IPv4(v4[0], v4[1], v4[2], byte(1))
		edgeProxy = gatewayIP.String()
		ipaddr := net.IPv4(v4[0], v4[1], v4[2], v4[3])
		log.DebugLog(log.DebugLevelMexos, "allocated ip addr", "role", role, "ipaddr", ipaddr)
		if role == k8smasterRole {
			if snd == nil {
				log.DebugLog(log.DebugLevelMexos, "k8s master, no existing subnet, creating subnet", "name", sn)
				err = CreateSubnet(ni.CIDR, GetMEXNetwork(), edgeProxy, sn, false)
				if err != nil {
					return err
				}
				//TODO: consider adding tags to subnet
				err = AddRouterSubnet(mexRouter, sn)
				if err != nil {
					return fmt.Errorf("cannot add router %s to subnet %s, %v", mexRouter, sn, err)
				}
			} else {
				log.DebugLog(log.DebugLevelMexos, "will not create subnet since it exists", "name", snd)
			}
			ipaddr = net.IPv4(v4[0], v4[1], v4[2], byte(2))
		}
		//XXX need to tell agent to add route for the cidr
		//+1 because gatway is at .1
		//master node num is 1
		//so, master node will always have .2
		//XXX master always at X.X.X.2
		netID = GetMEXNetwork() + ",v4-fixed-ip=" + ipaddr.String()
		masteripaddr := net.IPv4(v4[0], v4[1], v4[2], byte(2))
		masterIP = masteripaddr.String()
		log.DebugLog(log.DebugLevelMexos, "k8s master ip addr", "netID", netID, "ipaddr", ipaddr, "masterip", masterIP)
	} else {
		// NOT k8s case
		// for now just agent stuff.
		log.DebugLog(log.DebugLevelMexos, "create mex kvm, plain kvm, not kubernetes case")
		edgeProxy, err = GetExternalGateway(netID)
		if err != nil {
			return fmt.Errorf("can't get external gateway for %s, %v", netID, err)
		}
		log.DebugLog(log.DebugLevelMexos, "external gateway", "external gateway, edgeproxy", edgeProxy)

		rd, rderr := GetRouterDetail(mexRouter)
		if rderr != nil {
			return fmt.Errorf("can't get router detail for %s, %v", mexRouter, rderr)
		}
		log.DebugLog(log.DebugLevelMexos, "router detail", "detail", rd)
		reg, regerr := GetRouterDetailExternalGateway(rd)
		if regerr != nil {
			//return fmt.Errorf("can't get router detail external gateway, %v", regerr)
			log.DebugLog(log.DebugLevelMexos, "can't get router detail, not fatal")
		}
		if reg != nil && len(reg.ExternalFixedIPs) > 0 {
			fip := reg.ExternalFixedIPs[0]
			log.DebugLog(log.DebugLevelMexos, "external fixed ips", "ips", fip)
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
		} else {
			log.DebugLog(log.DebugLevelMexos, "can't get external fixed ips list from router detail external gateway, not fatal")
			privRouterIP = ""
			privNet = ""
		}
	}
	log.DebugLog(log.DebugLevelMexos, "creating a new kvm", "name", name, "skipk8s", skipk8s, "masterip", masterIP,
		"privnet", privNet, "privrouterip", privRouterIP, "tags", tags, "tenant", tenant)
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
		log.DebugLog(log.DebugLevelMexos, "error creating mex kvm", "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "ok done creating mex kvm", "name", name)
	return nil
}

func getNewSubnetRange(id int, v4a []byte, sits []string, sl []Subnet) (*string, error) {
	var cidr string
	for newID := id + 1; newID < eMEXSubnetLimit; newID++ {
		cidr = fmt.Sprintf("%d.%d.%d.%d/%s", v4a[0], v4a[1], v4a[2], newID, sits[1])
		found := false
		for _, snn := range sl {
			sdd, err := GetSubnetDetail(snn.ID)
			if err != nil {
				return nil, fmt.Errorf("cannot get subnet detail %s, %v", snn.Name, err)
			}
			if sdd.CIDR == cidr {
				found = true
			}
		}
		if !found {
			return &cidr, nil
		}
	}
	return nil, fmt.Errorf("can't find subnet range, last tried %s", cidr)
}

//DestroyMEXKVM deletes the MEX KVM instance. If server instance is k8s-master,
//  first remove router from subnet which was created for it. Then remove subnet before
//  deleting server KVM instance.
func DestroyMEXKVM(name, role string) error {
	log.DebugLog(log.DebugLevelMexos, "delete mex kvm server", "name", name, "role", role)
	err := DeleteServer(name)
	if err != nil {
		return fmt.Errorf("can't delete %s, %v", name, err)
	}
	if role == k8smasterRole {
		sn := "subnet-" + name
		rn := GetMEXExternalRouter()

		log.DebugLog(log.DebugLevelMexos, "removing router from subnet", "router", rn, "subnet", sn)
		err := RemoveRouterSubnet(rn, sn)
		if err != nil {
			return fmt.Errorf("can't remove router %s from subnet %s, %v", rn, sn, err)
		}

		//XXX This may not work until all nodes are removed, since
		//   IP addresses are allocated out of this subnet
		//   All nodes should be deleted first.
		log.DebugLog(log.DebugLevelMexos, "deleting subnet", "name", sn)
		err = DeleteSubnet(sn)
		if err != nil {
			return fmt.Errorf("can't delete subnet %s, %v", sn, err)
		}
	}
	return nil
}

//ParseNetSpec decodes netspec string
func ParseNetSpec(netSpec string) (*NetSpecInfo, error) {
	ni := &NetSpecInfo{}
	if netSpec == "" {
		return nil, fmt.Errorf("empty netspec")
	}
	items := strings.Split(netSpec, ",")
	if len(items) < 3 {
		return nil, fmt.Errorf("malformed net spec, insufficient items")
	}
	ni.Kind = items[NetTypeVal]
	ni.Name = items[NetNameVal]
	ni.CIDR = items[NetCIDRVal]
	if len(items) == 4 {
		ni.Options = items[NetOptVal]
	}
	if len(items) > 5 {
		ni.Extra = items[NetOptVal+1:]
	}
	switch items[NetTypeVal] {
	case "priv-subnet":
		return ni, nil
	case "external-ip":
		return ni, nil
	default:
		log.DebugLog(log.DebugLevelMexos, "error, invalid NetTypeVal", "net-type-val", items[NetTypeVal])
	}
	return nil, fmt.Errorf("unsupported netspec type")
}
