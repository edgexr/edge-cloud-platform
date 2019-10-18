package mexos

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	valid "github.com/asaskevich/govalidator"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vmspec"
	ssh "github.com/mobiledgex/golang-ssh"
)

//MEXRootLB has rootLB data
type MEXRootLB struct {
	Name string
	IP   string
}

var rootLBLock sync.Mutex

var MEXRootLBMap = make(map[string]*MEXRootLB)

//NewRootLB gets a new rootLB instance
func NewRootLB(ctx context.Context, rootLBName string) (*MEXRootLB, error) {
	rootLBLock.Lock()
	defer rootLBLock.Unlock()

	log.SpanLog(ctx, log.DebugLevelMexos, "getting new rootLB", "rootLBName", rootLBName)
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

func getRootLB(ctx context.Context, name string) (*MEXRootLB, error) {
	rootLB, ok := MEXRootLBMap[name]
	if !ok {
		return nil, fmt.Errorf("can't find rootlb %s", name)
	}
	if rootLB == nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "getrootlb, rootLB is null")
	}
	return rootLB, nil
}

var rootLBPorts = []int{
	int(cloudcommon.RootLBL7Port), // L7 access port
}

//CreateRootLB creates a seed presence node in cloudlet that also becomes first Agent node.
//  It also sets up first basic network router and subnet, ready for running first MEX agent.
func CreateRootLB(ctx context.Context, rootLB *MEXRootLB, vmspec *vmspec.VMCreationSpec, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "enable rootlb", "name", rootLB.Name, "vmspec", vmspec)
	if rootLB == nil {
		return fmt.Errorf("cannot enable rootLB, rootLB is null")
	}
	if GetCloudletExternalNetwork() == "" {
		return fmt.Errorf("enable rootlb, missing external network in manifest")
	}

	err := PrepNetwork(ctx)
	if err != nil {
		return err
	}
	sl, err := ListServers(ctx)
	if err != nil {
		return err
	}
	found := 0
	for _, s := range sl {
		if s.Name == rootLB.Name {
			log.SpanLog(ctx, log.DebugLevelMexos, "found existing rootlb", "server", s)
			found++
		}
	}
	if found == 0 {
		log.SpanLog(ctx, log.DebugLevelMexos, "not found existing server", "name", rootLB.Name)
		err := HeatCreateRootLBVM(ctx, rootLB.Name, rootLB.Name, vmspec, updateCallback)
		if err != nil {
			log.InfoLog("error while creating RootLB VM", "name", rootLB.Name, "error", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelMexos, "created VM", "name", rootLB.Name)
	} else {
		log.SpanLog(ctx, log.DebugLevelMexos, "re-using existing kvm instance", "name", rootLB.Name)
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "done enabling rootlb", "name", rootLB.Name)

	return nil
}

//SetupRootLB prepares the RootLB. It will optionally create the rootlb if the createRootLBFlavor
// is not blank and no existing server found
func SetupRootLB(ctx context.Context, rootLBName string, rootLBSpec *vmspec.VMCreationSpec, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "SetupRootLB", "rootLBSpec", rootLBSpec)
	//fqdn is that of the machine/kvm-instance running the agent
	if !valid.IsDNSName(rootLBName) {
		return fmt.Errorf("fqdn %s is not valid", rootLBName)
	}
	rootLB, err := getRootLB(ctx, rootLBName)
	if err != nil {
		return fmt.Errorf("cannot find rootlb in map %s", rootLBName)
	}
	sd, err := GetServerDetails(ctx, rootLBName)
	if err == nil && sd.Name == rootLBName {
		log.SpanLog(ctx, log.DebugLevelMexos, "server with same name as rootLB exists", "rootLBName", rootLBName)
	} else if rootLBSpec != nil {
		err = CreateRootLB(ctx, rootLB, rootLBSpec, updateCallback)
		if err != nil {
			log.InfoLog("can't create agent", "name", rootLB.Name, "err", err)
			return fmt.Errorf("Failed to enable root LB %v", err)
		}
	}

	// setup SSH access to cloudlet for CRM
	log.SpanLog(ctx, log.DebugLevelMexos, "setup security group for SSH access")
	groupName := GetCloudletSecurityGroup()
	my_ip, err := GetExternalPublicAddr(ctx)
	if err != nil {
		// this is not necessarily fatal
		log.InfoLog("cannot fetch public ip", "err", err)
	} else {
		if err := AddSecurityRuleCIDR(ctx, my_ip, "tcp", groupName, "22"); err != nil {
			log.SpanLog(ctx, log.DebugLevelMexos, "cannot add security rule for ssh access", "error", err, "ip", my_ip)
			return fmt.Errorf("unable to add security rule for ssh access, err: %v", err)
		}
	}

	err = WaitForRootLB(ctx, rootLB)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "timeout waiting for agent to run", "name", rootLB.Name)
		return fmt.Errorf("Error waiting for rootLB %v", err)
	}
	extIP, err := GetServerIPAddr(ctx, GetCloudletExternalNetwork(), rootLBName)
	if err != nil {
		return fmt.Errorf("cannot get rootLB IP %sv", err)
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "set rootLB IP to", "ip", extIP)
	rootLB.IP = extIP

	client, err := SetupSSHUser(ctx, rootLB, SSHUser)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "Copy resource-tracker to rootLb", "rootLb", rootLBName)
	err = CopyResourceTracker(client)
	if err != nil {
		return fmt.Errorf("cannot copy resource-tracker to rootLb %v", err)
	}

	err = LBAddRouteAndSecRules(ctx, client, rootLBName)
	if err != nil {
		return fmt.Errorf("failed to LBAddRouteAndSecRules %v", err)
	}
	if err = ActivateFQDNA(ctx, rootLBName, extIP); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "DNS A record activated", "name", rootLB.Name)
	return nil
}

//WaitForRootLB waits for the RootLB instance to be up and copies of SSH credentials for internal networks.
//  Idempotent, but don't call all the time.
func WaitForRootLB(ctx context.Context, rootLB *MEXRootLB) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "wait for rootlb", "name", rootLB.Name)
	if rootLB == nil {
		return fmt.Errorf("cannot wait for lb, rootLB is null")
	}

	extNet := GetCloudletExternalNetwork()
	if extNet == "" {
		return fmt.Errorf("waiting for lb, missing external network in manifest")
	}
	client, err := GetSSHClient(ctx, rootLB.Name, extNet, SSHUser)
	if err != nil {
		return err
	}
	running := false
	for i := 0; i < 10; i++ {
		log.SpanLog(ctx, log.DebugLevelMexos, "waiting for rootlb...")
		_, err := client.Output("sudo grep -i 'Finished mobiledgex init' /var/log/mobiledgex.log")
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelMexos, "rootlb is running", "name", rootLB.Name)
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
	log.SpanLog(ctx, log.DebugLevelMexos, "done waiting for rootlb", "name", rootLB.Name)

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

// This function copies resource-tracker from crm to rootLb - we need this to provide docker metrics
func CopyResourceTracker(client ssh.Client) error {
	path, err := exec.LookPath("resource-tracker")
	if err != nil {
		return err
	}
	err = SCPFilePath(client, path, "/tmp/resource-tracker")
	if err != nil {
		return err
	}
	// copy to /usr/local/bin/resource-tracker
	cmd := fmt.Sprintf("sudo cp /tmp/resource-tracker /usr/local/bin/resource-tracker")
	_, err = client.Output(cmd)
	if err != nil {
		return err
	}
	// make it executable
	cmd = fmt.Sprintf("sudo chmod a+rx /usr/local/bin/resource-tracker")
	_, err = client.Output(cmd)
	return err
}
