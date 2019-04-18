package mexos

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	valid "github.com/asaskevich/govalidator"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

//MEXRootLB has rootLB data
type MEXRootLB struct {
	Name string
	IP   string
}

var rootLBLock sync.Mutex

var MEXRootLBMap = make(map[string]*MEXRootLB)

//NewRootLB gets a new rootLB instance
func NewRootLB(rootLBName string) (*MEXRootLB, error) {
	rootLBLock.Lock()
	defer rootLBLock.Unlock()

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
	rootLBLock.Lock()
	defer rootLBLock.Unlock()
	delete(MEXRootLBMap, rootLBName)
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
}

//CreateRootLB creates a seed presence node in cloudlet that also becomes first Agent node.
//  It also sets up first basic network router and subnet, ready for running first MEX agent.
func CreateRootLB(rootLB *MEXRootLB, platformFlavor string) error {
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
		ni, err := ParseNetSpec(GetCloudletNetworkScheme())
		if err != nil {
			return err
		}
		// lock here to avoid getting the same floating IP; we need to lock until the stack is done
		// Floating IPs are allocated both by VM and cluster creation
		if ni.FloatingIPNet != "" {
			heatStackLock.Lock()
			defer heatStackLock.Unlock()
		}
		vmp, err := GetVMParams(
			RootLBVMDeployment,
			rootLB.Name,
			platformFlavor,
			GetCloudletOSImage(),
			"", // AuthPublicKey
			"", // AccessPorts
			"", // DeploymentManifest
			"", // Command
			ni,
		)
		if err != nil {
			return fmt.Errorf("Unable to get VM params: %v", err)
		}
		err = HeatCreateVM(vmp, rootLB.Name, VmTemplate)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error while creating VM", "error", err)
			return err
		}
		log.DebugLog(log.DebugLevelMexos, "created VM", "name", rootLB.Name)

	} else {
		log.DebugLog(log.DebugLevelMexos, "re-using existing kvm instance", "name", rootLB.Name)
	}
	log.DebugLog(log.DebugLevelMexos, "done enabling rootlb", "name", rootLB.Name)

	return nil
}

//SetupRootLB prepares the RootLB. It will optionally create the rootlb if the createRootLBFlavor
// is not blank and no existing server found
func SetupRootLB(rootLBName string, createRootLBFlavor string) error {
	log.DebugLog(log.DebugLevelMexos, "SetupRootLB", "createRootLBFlavor", createRootLBFlavor)
	//fqdn is that of the machine/kvm-instance running the agent
	if !valid.IsDNSName(rootLBName) {
		return fmt.Errorf("fqdn %s is not valid", rootLBName)
	}
	rootLB, err := getRootLB(rootLBName)
	if err != nil {
		return fmt.Errorf("cannot find rootlb in map %s", rootLBName)
	}
	sd, err := GetServerDetails(rootLBName)
	if err == nil && sd.Name == rootLBName {
		log.DebugLog(log.DebugLevelMexos, "server with same name as rootLB exists", "rootLBName", rootLBName)
	} else if createRootLBFlavor != "" {
		err = CreateRootLB(rootLB, createRootLBFlavor)
		if err != nil {
			log.InfoLog("can't create agent", "name", rootLB.Name, "err", err)
			return fmt.Errorf("Failed to enable root LB %v", err)
		}
	}
	err = WaitForRootLB(rootLB)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "timeout waiting for agent to run", "name", rootLB.Name)
		return fmt.Errorf("Error waiting for rootLB %v", err)
	}
	extIP, err := GetServerIPAddr(GetCloudletExternalNetwork(), rootLBName)
	if err != nil {
		return fmt.Errorf("cannot get rootLB IP %sv", err)
	}
	log.DebugLog(log.DebugLevelMexos, "set rootLB IP to", "ip", extIP)
	rootLB.IP = extIP

	client, err := SetupSSHUser(rootLB, SSHUser)
	if err != nil {
		return err
	}
	err = LBAddRouteAndSecRules(client, rootLBName)
	if err != nil {
		return fmt.Errorf("failed to LBAddRouteAndSecRules %v", err)
	}
	if err = ActivateFQDNA(rootLBName, extIP); err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "DNS A record activated", "name", rootLB.Name)
	err = GetHTPassword(rootLB.Name)
	if err != nil {
		return fmt.Errorf("can't download htpassword %v", err)
	}
	return RunMEXOSAgentService(client)
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
	client, err := GetSSHClient(rootLB.Name, extNet, SSHUser)
	if err != nil {
		return err
	}
	running := false
	for i := 0; i < 10; i++ {
		log.DebugLog(log.DebugLevelMexos, "waiting for rootlb...")
		_, err := client.Output("sudo grep 'Finished mobiledgex init' /var/log/mobiledgex.log")
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

// GetCloudletSharedRootLBFlavor gets the flavor from defaults
// or environment variables
func GetCloudletSharedRootLBFlavor(flavor *edgeproto.Flavor) error {
	ram := os.Getenv("MEX_SHARED_ROOTLB_RAM")
	var err error
	if ram != "" {
		flavor.Ram, err = strconv.ParseUint(ram, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Ram = 4096
	}
	vcpus := os.Getenv("MEX_SHARED_ROOTLB_VCPUS")
	if vcpus != "" {
		flavor.Vcpus, err = strconv.ParseUint(vcpus, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Vcpus = 2
	}
	disk := os.Getenv("MEX_SHARED_ROOTLB_DISK")
	if disk != "" {
		flavor.Disk, err = strconv.ParseUint(disk, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Disk = 40
	}
	return nil
}
