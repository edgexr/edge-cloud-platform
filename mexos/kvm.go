package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

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

	var masterIP, privRouterIP, privNet, edgeProxy string
	var err error
	//if role == "mex-agent-node" docker will be installed automatically
	if netSpec == "" {
		return fmt.Errorf("empty netspec")
	}
	if err != nil {
		return fmt.Errorf("can't parse netSpec %s, %v", netSpec, err)
	}
	if role == k8smasterRole || role == k8snodeRole {
		//impossible
		return fmt.Errorf("k8s VM creation is via Heat")
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
