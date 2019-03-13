package mexos

import (
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

//MEXRootLB has rootLB data
type MEXRootLB struct {
	Name string
	IP   string
}

var MEXRootLBMap = make(map[string]*MEXRootLB)

//NewRootLB gets a new rootLB instance
func NewRootLB(rootLBName string) (*MEXRootLB, error) {
	log.DebugLog(log.DebugLevelMexos, "getting new rootLB", "rootLBName", rootLBName)
	if _, ok := MEXRootLBMap[rootLBName]; ok {
		return nil, fmt.Errorf("rootlb %s already exists", rootLBName)
	}
	newRootLB := &MEXRootLB{Name: rootLBName}
	MEXRootLBMap[rootLBName] = newRootLB
	return newRootLB, nil
}

//DeleteRootLB to be called by code that called NewRootLB
func DeleteRootLB(rootLBName string) {
	delete(MEXRootLBMap, rootLBName) //no mutex because caller should be serializing New/Delete in a control loop
}

func getRootLB(name string) (*MEXRootLB, error) {
	rootLB, ok := MEXRootLBMap[name]
	if !ok {
		return nil, fmt.Errorf("can't find rootlb %s", name)
	}
	if rootLB == nil {
		log.DebugLog(log.DebugLevelMexos, "getrootlb, rootLB is null")
	}
	return rootLB, nil
}

var rootLBPorts = []int{
	18889, //mexosagent HTTP server
	//18888, //mexosagent GRPC server
	//443, //mexosagent reverse proxy HTTPS
	//8001,  //kubectl proxy
	//6443, //kubernetes control
	//8000,  //mex k8s join token server
}

//TODO more than one kubectl proxy, one per hosted  cluster

//EnableRootLB creates a seed presence node in cloudlet that also becomes first Agent node.
//  It also sets up first basic network router and subnet, ready for running first MEX agent.
func EnableRootLB(rootLB *MEXRootLB, cloudletKey *edgeproto.CloudletKey) error {
	log.DebugLog(log.DebugLevelMexos, "enable rootlb", "name", rootLB.Name)
	if rootLB == nil {
		return fmt.Errorf("cannot enable rootLB, rootLB is null")
	}
	if GetCloudletExternalNetwork() == "" {
		return fmt.Errorf("enable rootlb, missing external network in manifest")
	}

	err := PrepNetwork()
	if err != nil {
		return err
	}
	sl, err := ListServers()
	if err != nil {
		return err
	}
	found := 0
	for _, s := range sl {
		if s.Name == rootLB.Name {
			log.DebugLog(log.DebugLevelMexos, "found existing rootlb", "server", s)
			found++
		}
	}
	if found == 0 {
		log.DebugLog(log.DebugLevelMexos, "not found existing server", "name", rootLB.Name)
		netspec := fmt.Sprintf("external-ip,%s", GetCloudletExternalNetwork())
		//if strings.Contains(mf.Spec.Options, "dhcp") {  TODO
		netspec = netspec + ",dhcp"
		//}
		flavor := GetCloudletRootLBFlavor()
		cf, err := GetClusterFlavor(flavor)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "invalid platform flavor, can't create rootLB")
			return fmt.Errorf("cannot create rootLB invalid platform flavor %v", err)
		}

		tags := cloudletKey.Name + "-tag"

		log.DebugLog(log.DebugLevelMexos, "creating agent node kvm", "netspec", netspec)
		err = CreateMEXKVM(rootLB.Name,
			"mex-agent-node", //important, don't change
			netspec,
			tags,
			GetCloudletTenant(),
			1,
			nil, // cluster not needed for rootlb
			cf.PlatformFlavor,
		)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error while creating mex kvm", "error", err)
			return err
		}
		log.DebugLog(log.DebugLevelMexos, "created kvm instance", "name", rootLB.Name)

		//rootLBIPaddr, ierr := GetServerIPAddr(GetCloudletExternalNetwork(), rootLB.Name)
		// if ierr != nil {
		// 	log.DebugLog(log.DebugLevelMexos, "cannot get rootlb IP address", "error", ierr)
		// 	return fmt.Errorf("created rootlb but cannot get rootlb IP")
		// }
		ruleName := GetCloudletSecurityRule()
		//privateNetCIDR := strings.Replace(defaultPrivateNetRange, "X", "0", 1)
		allowedClientCIDR := GetAllowedClientCIDR()
		for _, p := range rootLBPorts {
			portString := fmt.Sprintf("%d", p)
			if err := AddSecurityRuleCIDR(allowedClientCIDR, "tcp", ruleName, portString); err != nil {
				log.DebugLog(log.DebugLevelMexos, "warning, cannot add security rule", "error", err, "cidr", allowedClientCIDR, "port", p, "rule", ruleName)
			}
		}
		//TODO: removal of security rules. Needs to be done for general resource per VM object.
		//    Add annotation to the running VM. When VM is removed, go through annotations
		//   and undo the resource allocations, like security rules, etc.
	} else {
		log.DebugLog(log.DebugLevelMexos, "re-using existing kvm instance", "name", rootLB.Name)
	}
	log.DebugLog(log.DebugLevelMexos, "done enabling rootlb", "name", rootLB.Name)

	return nil
}

//WaitForRootLB waits for the RootLB instance to be up and copies of SSH credentials for internal networks.
//  Idempotent, but don't call all the time.
func WaitForRootLB(rootLB *MEXRootLB) error {
	log.DebugLog(log.DebugLevelMexos, "wait for rootlb", "name", rootLB.Name)
	if rootLB == nil {
		return fmt.Errorf("cannot wait for lb, rootLB is null")
	}

	extNet := GetCloudletExternalNetwork()
	if extNet == "" {
		return fmt.Errorf("waiting for lb, missing external network in manifest")
	}
	client, err := GetSSHClient(rootLB.Name, extNet, sshUser)
	if err != nil {
		return err
	}
	running := false
	for i := 0; i < 10; i++ {
		log.DebugLog(log.DebugLevelMexos, "waiting for rootlb...")
		_, err := client.Output("sudo grep 'all done' /var/log/mobiledgex.log") //XXX beware of use of word done
		if err == nil {
			log.DebugLog(log.DebugLevelMexos, "rootlb is running", "name", rootLB.Name)
			running = true
			//if err := CopySSHCredential(mf, rootLB.Name, GetCloudletExternalNetwork(), "root"); err != nil {
			//	return fmt.Errorf("can't copy ssh credential to RootLB, %v", err)
			//}
			break
		}
		time.Sleep(30 * time.Second)
	}
	if !running {
		return fmt.Errorf("while creating cluster, timeout waiting for RootLB")
	}
	log.DebugLog(log.DebugLevelMexos, "done waiting for rootlb", "name", rootLB.Name)

	return nil
}
