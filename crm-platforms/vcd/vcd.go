package vcd

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	gogotypes "github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
	"github.com/vmware/go-vcloud-director/v2/govcd"
)

// Note regarding govcd SDK:
// Most all types in govcd are arranged as a containerized type in govcd that compose Client and
// specific methods, with the business end of the type in types.go. example found in vdc.go:
//
//   type Vdc struct {
//  	  Vdc    *types.Vdc
//	  client *Client
//   }
//
// The method calls are accessed via the "outer" govcd.Vdc object utilizing the client object, and operate on
// the 'inner' types.Vdc object.
//
var vcdProviderVersion = "-0.1-alpha"

type VcdPlatform struct {
	vmProperties *vmlayer.VMProperties
	vcdVars      map[string]string
	caches       *platform.Caches
	Creds        *VcdConfigParams
	TestMode     bool
	Verbose      bool
}

type VcdConfigParams struct {
	User     string
	Password string
	Org      string
	Href     string
	VDC      string
	Insecure bool
	Token    string
}

type VAppMap map[string]*govcd.VApp
type VMMap map[string]*govcd.VM
type NetMap map[string]*govcd.OrgVDCNetwork

func (v *VcdPlatform) GetType() string {
	return "vcd"
}

func (v *VcdPlatform) InitProvider(ctx context.Context, caches *platform.Caches, stage vmlayer.ProviderInitStage, updateCallback edgeproto.CacheUpdateCallback) error {

	v.Verbose = true

	log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider for Vcd 1", "stage", stage)
	v.Verbose = v.GetVcdVerbose()
	v.InitData(ctx, caches)

	log.SpanLog(ctx, log.DebugLevelInfra, "Discover resources for", "Org", v.Creds.Org)
	err := v.ImportDataFromInfra(ctx)
	if err != nil {
		return fmt.Errorf("ImportDataFromInfra failed: %s", err.Error())
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider Discovery Complete", "stage", stage)

	err = v.SetProviderSpecificProps(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (v *VcdPlatform) InitData(ctx context.Context, caches *platform.Caches) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitData caches set")
	v.caches = caches
}

func (v *VcdPlatform) ImportDataFromInfra(ctx context.Context) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "ImportDataFromInfra")
	err := v.GetPlatformResources(ctx)
	if err != nil {
		return fmt.Errorf("Error retrieving Platform Resources: %s", err.Error())
	}
	return nil
}

func (v *VcdPlatform) GetPlatformResourceInfo(ctx context.Context) (*vmlayer.PlatformResources, error) {

	var resources = vmlayer.PlatformResources{}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetPlatformResourceInfo ")

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return nil, fmt.Errorf(NoVCDClientInContext)
	}
	resources.CollectTime, _ = gogotypes.TimestampProto(time.Now())
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, err
	}

	c_capacity := vdc.Vdc.ComputeCapacity
	for _, cap := range c_capacity {
		resources.VCpuMax = uint64(cap.CPU.Limit)
		resources.VCpuUsed = uint64(cap.CPU.Used)
		resources.MemMax = uint64(cap.Memory.Limit)
		resources.MemUsed = uint64(cap.Memory.Used)
	}
	return &resources, nil
}

func (v *VcdPlatform) GetResourceID(ctx context.Context, resourceType vmlayer.ResourceType, resourceName string) (string, error) {

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return "", fmt.Errorf(NoVCDClientInContext)
	}
	// VM, Subnet and SecGrp are the current potential values of Type
	// The only one we have so far is VMs, (subnets soon, and secGrps eventually)
	if resourceType == vmlayer.ResourceTypeVM {
		vm, err := v.FindVMByName(ctx, resourceName, vcdClient)
		if err != nil {
			return "", fmt.Errorf("resource %s not found", resourceName)
		}
		return vm.VM.ID, nil
	} else if resourceType == vmlayer.ResourceTypeSecurityGroup {
		// Get the security Group ID for default XXX
		return "1234", nil
	}
	return "", fmt.Errorf("GetResourceID not implemented for resource type: %s name %s", resourceType, resourceName)
}

// check server ready without cloudlets
//
// CheckServerReady
func (v VcdPlatform) CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady", "serverName", serverName)
	detail, err := v.GetServerDetail(ctx, serverName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady GetServerDetail", "err", err)
		return err
	}
	out := ""
	if detail.Status == vmlayer.ServerActive {
		//out, err = client.Output("systemctl status mobiledgex.service")
		log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady Mobiledgex service status", "serverName", serverName, "out", out, "err", err)
		return nil
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady Mobiledgex service status (recovered) ", "serverName", serverName, "out", out, "err", err)
		return nil // fmt.Errorf("Server %s status: %s", serverName, detail.Status)
	}
}

// Retrieve our top level Org object
func (v *VcdPlatform) GetOrg(ctx context.Context, vcdClient *govcd.VCDClient) (*govcd.Org, error) {
	org, err := vcdClient.GetOrgByName(v.Creds.Org)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetOrgByName failed", "org", v.Creds.Org, "err", err)
		return nil, fmt.Errorf("GetOrgByName error %s", err.Error())
	}
	return org, nil
}

// Retrieve our refreshed vdc object
func (v *VcdPlatform) GetVdc(ctx context.Context, vcdClient *govcd.VCDClient) (*govcd.Vdc, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVdc")

	org, err := v.GetOrg(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVdc GetOrg return error", "vdc", v.Creds.VDC, "org", v.Creds.Org, "err", err)
		return nil, err
	}

	vdc, err := org.GetVDCByName(v.Creds.VDC, true)
	if err != nil {
		return nil, err
	}
	return vdc, err

}

// return everything else,
func (v *VcdPlatform) GetPlatformResources(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetPlatformResources")
	return nil
}

func (v *VcdPlatform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	return v.Creds.Href, nil
}

func (v *VcdPlatform) ImportImage(ctx context.Context, folder, imageFile string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ImportImage", "imageFile", imageFile, "folder", folder)

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	// first delete anything that may be there for this image
	v.DeleteImage(ctx, folder, imageFile)
	// .ova's are the unit of upload to our catalog (but could be an ovf + vmdk)
	cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
	if err != nil {
		return err
	}
	// ovaFile, itemName, description, uploadPieceSize xxx is folder appropriate for itemName?
	cat.UploadOvf(imageFile, folder+"-tmpl", "mex base iamge", 4*1024)
	return nil
}

func (v *VcdPlatform) DeleteImage(ctx context.Context, folder, image string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage", "image", image)
	// Fetch the folder-tmpl item and call item.Delete()
	// TBI
	return nil
}

// Assuming Vcd is more similar to Vsphere rather than vmPool or OpenStack
// alphanumeric plus -_. first char must be alpha, <= 255 chars.
func (v *VcdPlatform) NameSanitize(name string) string {
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "",
		"/", "_",
		"!", "")
	str := r.Replace(name)
	if str == "" {
		return str
	}
	if !unicode.IsLetter(rune(str[0])) {
		// first character must be alpha
		str = "a" + str
	}
	if len(str) > 255 {
		str = str[:254]
	}
	return str
}

// IdSanitize is NameSanitize plus removing "."
func (v *VcdPlatform) IdSanitize(name string) string {
	str := v.NameSanitize(name)
	str = strings.ReplaceAll(str, ".", "-")
	return str
}

func (v *VcdPlatform) GetServerDetail(ctx context.Context, serverName string) (*vmlayer.ServerDetail, error) {

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return nil, fmt.Errorf(NoVCDClientInContext)
	}
	vm, err := v.FindVMByName(ctx, serverName, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail not found", "vmname", serverName)
		return nil, err
	}
	detail := vmlayer.ServerDetail{}
	detail.Name = vm.VM.Name
	detail.ID = vm.VM.ID
	vmStatus, err := vm.GetStatus()
	if err != nil {
		return nil, err
	}

	if vmStatus == "POWERED_ON" {
		detail.Status = vmlayer.ServerActive
	} else if vmStatus == "POWERED_OFF" {
		detail.Status = vmlayer.ServerShutoff
	} else {
		detail.Status = vmStatus
	}

	addresses, err := v.GetVMAddresses(ctx, vm)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail err getting VMAddresses for", "vmname", serverName, "err", err)
		return nil, err
	}
	detail.Addresses = addresses

	return &detail, nil

}

func (v *VcdPlatform) GetAllVMsForVdcByIntAddr(ctx context.Context, vcdClient *govcd.VCDClient) (VMMap, error) {
	vmMap := make(VMMap)

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return vmMap, err
	}
	netName := v.vmProperties.GetCloudletExternalNetwork()

	for _, r := range vdc.Vdc.ResourceEntities {
		for _, res := range r.ResourceEntity {
			if res.Type == "application/vnd.vmware.vcloud.vm+xml" {
				vm, err := v.FindVMByName(ctx, res.Name, vcdClient)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVMsForVdcByIntAddr FindVMByName error", "vm", res.Name, "error", err)
					return vmMap, err
				} else {
					if v.Verbose {
						log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVMsByIntAddr consider ", "vm", res.Name)
					}
					ncs, err := vm.GetNetworkConnectionSection()
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVMsByIntAddr GetNetworkConnectionSection failed", "error", err)
						return vmMap, err
					}
					// looking for internal network name
					for _, nc := range ncs.NetworkConnection {
						if nc.Network != netName {
							ip, err := v.GetAddrOfVM(ctx, vm, nc.Network)
							if err != nil {
								log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVapps GetAddrOfVapp ", "error", err)
								return vmMap, err
							}
							// We only want gateway addrs in this map so reject any addrs
							// that have other an .1 as the last octet
							//
							// Skip the vapp we're attempting to set
							if ip != "" {
							}
						}
					}
				}
			}
		}
	}
	return vmMap, nil
}

func (v *VcdPlatform) GetAllVAppsForVdcByIntAddr(ctx context.Context, vcdClient *govcd.VCDClient) (VAppMap, error) {

	vappMap := make(VAppMap)
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return vappMap, err
	}

	extNetName := v.vmProperties.GetCloudletExternalNetwork()

	for _, r := range vdc.Vdc.ResourceEntities {
		for _, res := range r.ResourceEntity {
			if res.Type == "application/vnd.vmware.vcloud.vApp+xml" {
				vapp, err := vdc.GetVAppByName(res.Name, true)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "GetVappByName", "Vapp", res.Name, "error", err)
					return vappMap, err
				} else {
					if v.Verbose {
						log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVappsByIntAddr consider ", "vapp", res.Name)
					}
					ncs, err := vapp.GetNetworkConnectionSection()
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVappsByIntAddr ", "error", err)
						return vappMap, err
					}
					// looking for internal network name
					for _, nc := range ncs.NetworkConnection {
						if nc.Network != extNetName {
							ip, err := v.GetAddrOfVapp(ctx, vapp, nc.Network)
							if err != nil {
								log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVapps GetAddrOfVapp ", "error", err)
								return vappMap, err
							}
							// We only want gateway addrs in this map so reject any addrs
							// that have other an .1 as the last octet
							//
							// Skip the vapp we're attempting to set
							if ip != "" {
								delimiter, err := Octet(ctx, ip, 2)
								if err != nil {
									log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVappsByIntAddr Octet failed", "err", err)
									return vappMap, err
								}
								addr := fmt.Sprintf("10.101.%d.1", delimiter)
								log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVappsByIntAddr add", "ip", ip, "vapp", res.Name)
								vappMap[addr] = vapp
							}
						}
						// else if it has no other nets, just skip it
					}
				}
			}
		}
	}
	return vappMap, nil

}

func (v *VcdPlatform) GetApiEndpointAddr(ctx context.Context) (string, error) {

	ip := v.GetVCDIP() // {vcdVars["VCD_IP"]
	apiUrl := ip + "/api"
	log.SpanLog(ctx, log.DebugLevelInfra, "GetApiEndpointAddr", "Href", apiUrl)
	return apiUrl, nil
}

func (v *VcdPlatform) GetVappServerSuffix() string {
	return "-vapp"
}

func (v *VcdPlatform) GetCloudletImageSuffix(ctx context.Context) string {
	return "-vcd.qcow2"
}

func (v *VcdPlatform) GetCloudletManifest(ctx context.Context, name, cloudletImagePath string, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletManifest", "name", name, "imagePath", cloudletImagePath)
	return "", nil
}

func (v *VcdPlatform) GetSessionTokens(ctx context.Context, vaultConfig *vault.Config, account string) (map[string]string, error) {
	return nil, fmt.Errorf("GetSessionTokens not supported in VcdPlatform")
}

// Return our current set of access vars
// For what exactly?
// where do I save it?
//
func (v *VcdPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {

	return fmt.Errorf("SaveCloudletAccessVars not implemented for vcd")

}

func (v *VcdPlatform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	return []edgeproto.InfraResource{}, nil
}

func (v *VcdPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	return &edgeproto.CloudletResourceQuotaProps{}, nil
}

func (v *VcdPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]*edgeproto.InfraResource) map[string]*edgeproto.InfraResource {
	resInfo := make(map[string]*edgeproto.InfraResource)
	return resInfo
}

func (v *VcdPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}
