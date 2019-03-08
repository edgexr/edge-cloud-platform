package mexos

import (
	"fmt"
	"net"
	"strings"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type NetSpecInfo struct {
	Kind, Name, CIDR, Options string
	Extra                     []string
}

func GetK8sNodeNameSuffix(clusterInst *edgeproto.ClusterInst) string {
	cloudletName := clusterInst.Key.CloudletKey.Name
	clusterName := clusterInst.Key.ClusterKey.Name
	return NormalizeName(cloudletName + "-" + clusterName)
}

/* TODO: Fix for swarm
//CreateQCOW2AppManifest creates qcow2 app
func CreateQCOW2AppManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "create qcow2 vm based app")
	//TODO: support other URI: file://, nfs://, ftp://, git://, or embedded as base64 string
	if !strings.HasPrefix(mf.Spec.Image, "http://") &&
		!strings.HasPrefix(mf.Spec.Image, "https://") {
		return fmt.Errorf("unsupported qcow2 image spec %s", mf.Spec.Image)
	}
	if !strings.Contains(mf.Spec.Flavor, "qcow2") {
		return fmt.Errorf("unsupported qcow2 flavor %s", mf.Spec.Flavor)
	}
	if err := ValidateCommon(mf); err != nil {
		return err
	}

	savedQcowName := mf.Metadata.Name + ".qcow2" // XXX somewhere safe instead
	alreadyExist := false
	images, err := ListImages(mf)
	if err != nil {
		return fmt.Errorf("cannot list openstack images, %v", err)
	}
	for _, img := range images {
		if img.Name == mf.Metadata.Name && img.Status == "active" {
			log.DebugLog(log.DebugLevelMexos, "warning, glance has image already", "name", mf.Metadata.Name)
			if !strings.Contains(mf.Spec.Flags, "force") {
				alreadyExist = true
			} else {
				log.DebugLog(log.DebugLevelMexos, "forced to download image again. delete existing glance image")
				if ierr := DeleteImage(mf, mf.Metadata.Name); ierr != nil {
					return fmt.Errorf("error deleting glance image %s, %v", mf.Metadata.Name, ierr)
				}
			}
		}
	}
	if !alreadyExist {
		log.DebugLog(log.DebugLevelMexos, "getting qcow2 image", "image", mf.Spec.Image, "name", savedQcowName)
		out, cerr := sh.Command("curl", "-s", "-o", savedQcowName, mf.Spec.Image).Output()
		if cerr != nil {
			return fmt.Errorf("error retrieving qcow image, %s, %s, %v", savedQcowName, out, cerr)
		}
		finfo, serr := os.Stat(savedQcowName)
		if serr != nil {
			if os.IsNotExist(serr) {
				return fmt.Errorf("downloaded qcow2 file %s does not exist, %v", savedQcowName, serr)
			}
			return fmt.Errorf("error looking for downloaded qcow2 file %v", serr)
		}
		if finfo.Size() < 1000 { //too small
			return fmt.Errorf("invalid downloaded qcow2 file %s", savedQcowName)
		}
		log.DebugLog(log.DebugLevelMexos, "qcow2 image being created", "image", mf.Spec.Image, "name", savedQcowName)
		err = CreateImage(mf, mf.Metadata.Name, savedQcowName)
		if err != nil {
			return fmt.Errorf("cannot create openstack glance image instance from %s, %v", savedQcowName, err)
		}
		log.DebugLog(log.DebugLevelMexos, "saved qcow image to glance", "name", mf.Metadata.Name)
		found := false
		for i := 0; i < 10; i++ {
			images, ierr := ListImages(mf)
			if ierr != nil {
				return fmt.Errorf("error while getting list of qcow2 glance images, %v", ierr)
			}
			for _, img := range images {
				if img.Name == mf.Metadata.Name && img.Status == "active" {
					found = true
					break
				}
			}
			if found {
				break
			}
			log.DebugLog(log.DebugLevelMexos, "waiting for the image to become active", "name", mf.Metadata.Name)
			time.Sleep(2 * time.Second)
		}
		if !found {
			return fmt.Errorf("timed out waiting for glance to activate the qcow2 image %s", mf.Metadata.Name)
		}
	}
	log.DebugLog(log.DebugLevelMexos, "qcow image is active in glance", "name", mf.Metadata.Name)
	if !strings.HasPrefix(mf.Spec.NetworkScheme, "external-ip,") { //XXX for now
		return fmt.Errorf("invalid network scheme for qcow2 kvm app, %s", mf.Spec.NetworkScheme)
	}
	items := strings.Split(mf.Spec.NetworkScheme, ",")
	if len(items) < 2 {
		return fmt.Errorf("can't find external network name in %s", mf.Spec.NetworkScheme)
	}
	extNetwork := items[1]
	opts := &OSServerOpt{
		Name:   mf.Metadata.Name,
		Image:  mf.Metadata.Name,
		Flavor: mf.Spec.ImageFlavor,
		NetIDs: []string{extNetwork},
	}
	//TODO properties
	//TODO userdata
	log.DebugLog(log.DebugLevelMexos, "calling create openstack kvm server", "opts", opts)
	err = CreateServer(opts)
	if err != nil {
		return fmt.Errorf("can't create openstack kvm server instance %v, %v", opts, err)
	}
	log.DebugLog(log.DebugLevelMexos, "created openstack kvm server", "opts", opts)
	return nil
}
*/

/*

func DeleteQCOW2AppManifest(mf *Manifest) error {
	if mf.Metadata.Name == "" {
		return fmt.Errorf("missing name, no openstack kvm to delete")
	}
	if err := DeleteServer(mf.Metadata.Name); err != nil {
		return fmt.Errorf("cannot delete openstack kvm %s, %v", mf.Metadata.Name, err)
	}
	return nil
}
*/

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
		image = GetCloudletOSImage()
	}
	if flavor == "" {
		return fmt.Errorf("Missing platform flavor")
	}
	if userdata == "" {
		userdata = GetCloudletUserData()
	}
	opts := &OSServerOpt{
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

	/* TODO: holepunch has not been used anywhere but need to investigate if we will want this
	   if GetCloudletHolePunch() != "" {
	   	props = append(props, "holepunch="+GetCloudletHolePunch()
	   }
	*/

	/* TODO: update has code for it in the init scripts, but has not been used because the cloudlet-specific files
	   are not present on the registry and nobody knew this existed.  This is for Venky to study.
	   if mf.Values.Registry.Update != "" {
	   	props = append(props, "update="+mf.Values.Registry.Update)
	   }
	*/

	opts.Properties = props
	//log.DebugLog(log.DebugLevelMexos, "create flavor MEX KVM", "flavor", flavor, "server opts", opts)
	log.DebugLog(log.DebugLevelMexos, "create flavor MEX KVM", "flavor", flavor)
	err = CreateServer(opts)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error creating flavor MEX KVM", "server opts", opts)
		return fmt.Errorf("can't create server, opts %v, %v", opts, err)
	}
	return nil
}

//CreateMEXKVM is easier way to create a MEX app capable KVM
//  role can be k8s-master, k8s-node, or something else
func CreateMEXKVM(name, role, netSpec, tags, tenant string, id int, clusterInst *edgeproto.ClusterInst, platformFlavor string) error {
	log.DebugLog(log.DebugLevelMexos, "createMEXKVM",
		"name", name, "role", role, "netSpec", netSpec,
		"tags", tags, "tenant", tenant, "id", id)
	mexRouter := GetCloudletExternalRouter()
	netID := GetCloudletExternalNetwork() //do we really want to default to ext?
	skipk8s := "yes"
	nameSuffix := ""
	if clusterInst != nil {
		nameSuffix = GetK8sNodeNameSuffix(clusterInst)
	}

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
		if ni.Name != GetCloudletMexNetwork() { //XXX for now
			return fmt.Errorf("netspec net name %s not equal to default MEX net %s", ni.Name, GetCloudletMexNetwork())
		}
		//XXX openstack bug - subnet does not take tags but description field can be used to tag stuff
		//   Use tag as part of name
		sn := ni.Name + "-subnet-" + nameSuffix
		log.DebugLog(log.DebugLevelMexos, "using subnet name", "subnet", sn)
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
				//log.DebugLog(log.DebugLevelMexos, "subnet for this cluster existed", "subnet detail", snd)
				log.DebugLog(log.DebugLevelMexos, "subnet for this cluster existed", "name", snd.Name)
				ni.CIDR = snd.CIDR
			}
			log.DebugLog(log.DebugLevelMexos, "allocated CIDR", "cidr", ni.CIDR)
		} else {
			if snd == nil {
				log.DebugLog(log.DebugLevelMexos, "error, subnet not found; this should not happen!", "name", sn)
				// should not happen
				return fmt.Errorf("subnet %s not found", sn)
			}
			id = id + MEXSubnetSeed
			log.DebugLog(log.DebugLevelMexos, "node id", "id", id)
			// worker nodes start at 100+id.
			// there may be many masters... allow for upto 100!
			//leave some space at end
			if id > MEXSubnetLimit {
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
				if sn.Subnet == ni.CIDR {
					log.DebugLog(log.DebugLevelMexos, "subnet exists with the same CIDR, find another range", "CIDR", ni.CIDR)
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
				err = CreateSubnet(ni.CIDR, GetCloudletMexNetwork(), edgeProxy, sn, false)
				if err != nil {
					return err
				}
				//TODO: consider adding tags to subnet
				err = AddRouterSubnet(mexRouter, sn)
				if err != nil {
					return fmt.Errorf("cannot add router %s to subnet %s, %v", mexRouter, sn, err)
				}
			} else {
				//log.DebugLog(log.DebugLevelMexos, "will not create subnet since it exists", "name", snd)
				log.DebugLog(log.DebugLevelMexos, "will not create subnet since it exists", "name", snd.Name)
			}
			ipaddr = net.IPv4(v4[0], v4[1], v4[2], byte(2))
		}
		//XXX need to tell agent to add route for the cidr
		//+1 because gatway is at .1
		//master node num is 1
		//so, master node will always have .2
		//XXX master always at X.X.X.2
		netID = GetCloudletMexNetwork() + ",v4-fixed-ip=" + ipaddr.String()
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
	if err != nil {
		return fmt.Errorf("cannot get flavor from tags '%s'", tags)
	}
	err = CreateFlavorMEXVM(name,
		GetCloudletOSImage(),
		platformFlavor,
		netID, // either external-net or internal-net,v4-fixed-ip=X.X.X.X
		GetCloudletUserData(),
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

func getNewSubnetRange(id int, v4a []byte, sits []string, sl []OSSubnet) (*string, error) {
	var cidr string
	for newID := id + 1; newID < MEXSubnetLimit; newID++ {
		cidr = fmt.Sprintf("%d.%d.%d.%d/%s", v4a[0], v4a[1], v4a[2], newID, sits[1])
		found := false
		for _, snn := range sl {
			if snn.Subnet == cidr {
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
func DestroyMEXKVM(name, role, clusterName string) error {
	//TODO send shutdown command to running VM. Left undone so we insteadi optionally
	// send ssh shutdown manually before deleting the KVM instance via API or mexctl.
	log.DebugLog(log.DebugLevelMexos, "delete mex kvm server", "name", name, "role", role)
	err := DeleteServer(name)
	if err != nil {
		return fmt.Errorf("can't delete %s, %v", name, err)
	}
	if role == k8smasterRole {
		sn := "subnet-" + clusterName
		rn := GetCloudletExternalRouter()

		log.DebugLog(log.DebugLevelMexos, "removing router from subnet", "router", rn, "subnet", sn)
		err := RemoveRouterSubnet(rn, sn)
		if err != nil {
			return fmt.Errorf("can't remove subnet %s from router %s, %v", sn, rn, err)
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
	log.DebugLog(log.DebugLevelMexos, "parsing netspec", "netspec", netSpec)
	items := strings.Split(netSpec, ",")
	if len(items) < 3 {
		return nil, fmt.Errorf("malformed net spec, insufficient items %v", items)
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
	log.DebugLog(log.DebugLevelMexos, "netspec info", "ni", ni, "items", items)
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
