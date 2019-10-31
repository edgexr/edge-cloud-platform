package mexos

// This file stores a global cloudlet infra properties object. The long term solution is for the controller to send this via the
// notification channel when the cloudlet is provisioned.   The controller will do the vault access and pass this data down; this
// is a stepping stone to start using edgepro data strucures to hold info abou the cloudlet rather than custom types and so the vault
// is still directly accessed here as are env variable to populate some variables

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var CloudletInfraCommon edgeproto.CloudletInfraCommon
var OpenstackProps edgeproto.OpenStackProperties

var MEXInfraVersion = "v2.0.42" //temporary until 2.0.5 available
var defaultOSImageName = "mobiledgex-" + MEXInfraVersion
var VaultAddr string

// NoConfigExternalRouter is used for the case in which we don't manage the external
// router and don't add ports to it ourself, as happens with Contrail.  The router does exist in
// this case and we use it to route from the LB to the pods
var NoConfigExternalRouter = "NOCONFIG"

// NoExternalRouter means there is no router at all and we connect the LB to the k8s pods on the same subnet
// this may eventually be the default and possibly only option
var NoExternalRouter = "NONE"

// Package level test mode variable
var testMode = false

// mapping of FQDNs the CRM knows about to externally mapped IPs. This
// is used mainly in lab environments that have NATed IPs which can be used to
// access the cloudlet externally but are not visible in any way to OpenStack
var mappedExternalIPs map[string]string

func getVaultCloudletPath(filePath, vaultAddr string) string {
	return fmt.Sprintf(
		"%s/v1/secret/data/cloudlet/openstack/%s",
		vaultAddr, filePath,
	)
}

func InitInfraCommon(ctx context.Context, vaultAddr string) error {
	if vaultAddr == "" {
		return fmt.Errorf("vaultAddr is not specified")
	}
	VaultAddr = vaultAddr
	mexEnvURL := getVaultCloudletPath("mexenv.json", vaultAddr)
	err := InternVaultEnv(ctx, mexEnvURL)
	if err != nil {
		if testMode {
			log.SpanLog(ctx, log.DebugLevelMexos, "failed to InternVaultEnv", "url", mexEnvURL, "err", err)
		} else {
			return fmt.Errorf("failed to InternVaultEnv %s: %v", mexEnvURL, err)
		}
	}
	CloudletInfraCommon.CfKey = os.Getenv("MEX_CF_KEY")
	if CloudletInfraCommon.CfKey == "" {
		if testMode {
			log.SpanLog(ctx, log.DebugLevelMexos, "Env variable MEX_CF_KEY not set")
		} else {
			return fmt.Errorf("Env variable MEX_CF_KEY not set")
		}
	}
	CloudletInfraCommon.CfUser = os.Getenv("MEX_CF_USER")
	if CloudletInfraCommon.CfKey == "" {
		if testMode {
			log.SpanLog(ctx, log.DebugLevelMexos, "Env variable MEX_CF_USER not set")
		} else {
			return fmt.Errorf("Env variable MEX_CF_USER not set")
		}
	}
	CloudletInfraCommon.DnsZone = "mobiledgex.net"
	CloudletInfraCommon.RegistryFileServer = "registry.mobiledgex.net"
	err = initMappedIPs()
	if err != nil {
		return fmt.Errorf("unable to init Mapped IPs: %v", err)
	}
	return nil
}

func InitOpenstackProps(ctx context.Context, operatorName, physicalName, vaultAddr string) error {
	openRcURL := getVaultCloudletPath(physicalName+"/openrc.json", vaultAddr)
	err := InternVaultEnv(ctx, openRcURL)
	if err != nil {
		return fmt.Errorf("failed to InternVaultEnv %s: %v", openRcURL, err)
	}
	VaultAddr = vaultAddr
	authURL := os.Getenv("OS_AUTH_URL")
	if strings.HasPrefix(authURL, "https") {
		caCertURL := getVaultCloudletPath(physicalName+"/os_cacert", vaultAddr)
		if caCertURL != "" {
			certFile := fmt.Sprintf("/tmp/%s.%s.cert", operatorName, physicalName)
			err := GetVaultDataToFile(caCertURL, certFile)
			if err != nil {
				return fmt.Errorf("failed to GetVaultDataToFile %s: %v", caCertURL, err)
			}
			os.Setenv("OS_CACERT", certFile)
		}
	}

	OpenstackProps.OpenRcVars = make(map[string]string)

	OpenstackProps.OsExternalNetworkName = os.Getenv("MEX_EXT_NETWORK")
	if OpenstackProps.OsExternalNetworkName == "" {
		OpenstackProps.OsExternalNetworkName = "external-network-shared"
	}

	OpenstackProps.OsImageName = os.Getenv("MEX_OS_IMAGE")
	if OpenstackProps.OsImageName == "" {
		OpenstackProps.OsImageName = defaultOSImageName
	}

	// defaulting some value
	OpenstackProps.OsExternalRouterName = os.Getenv("MEX_ROUTER")
	if OpenstackProps.OsExternalRouterName == "" {
		OpenstackProps.OsExternalRouterName = "mex-k8s-router-1"
	}
	OpenstackProps.OsMexNetwork = "mex-k8s-net-1"
	return nil
}

//GetCloudletExternalRouter returns default MEX external router name
func GetCloudletExternalRouter() string {
	//TODO validate existence and status
	return OpenstackProps.OsExternalRouterName
}

func GetCloudletExternalNetwork() string {
	// this will be unset if platform is not openstack
	// because InitOpenstackProps() will not have been called.
	return OpenstackProps.OsExternalNetworkName
}

// Utility functions that used to be within manifest.
//GetCloudletNetwork returns default MEX network, internal and prepped
func GetCloudletMexNetwork() string {
	//TODO validate existence and status
	return OpenstackProps.OsMexNetwork
}

func GetCloudletDNSZone() string {
	return CloudletInfraCommon.DnsZone
}

func GetCloudletNetworkScheme() string {
	return CloudletInfraCommon.NetworkScheme
}

func GetCloudletOSImage() string {
	return OpenstackProps.OsImageName
}

func GetCloudletRegistryFileServer() string {
	return CloudletInfraCommon.RegistryFileServer
}

func GetCloudletCFKey() string {
	return CloudletInfraCommon.CfKey
}

func GetCloudletCFUser() string {
	return CloudletInfraCommon.CfUser
}

func SetTestMode(tMode bool) {
	testMode = tMode
}

// GetCleanupOnFailure should be true unless we want to debug the failure,
// in which case this env var can be set to no.  We could consider making
// this configurable at the controller but really is only needed for debugging.
func GetCleanupOnFailure(ctx context.Context) bool {
	cleanup := os.Getenv("CLEANUP_ON_FAILURE")
	log.SpanLog(ctx, log.DebugLevelMexos, "GetCleanupOnFailure", "cleanup", cleanup)
	cleanup = strings.ToLower(cleanup)
	cleanup = strings.ReplaceAll(cleanup, "'", "")
	if cleanup == "no" || cleanup == "false" {
		return false
	}
	return true
}

// These not in the proto file yet because they may not change for a while
func GetCloudletTenant() string {
	return "null"
}
func GetCloudletSecurityGroup() string {
	sg := os.Getenv("MEX_SECURITY_GROUP")
	if sg == "" {
		return "default"
	}
	return sg
}
func GetCloudletMexosAgentPort() string {
	return "18889"
}

func GetCloudletFlavorMatchPattern() string {
	pattern := os.Getenv("FLAVOR_MATCH_PATTERN")
	if pattern == "" {
		return ".*"
	}
	return pattern
}

func GetCloudletCRMGatewayIPAndPort() (string, int) {
	gw := os.Getenv("MEX_CRM_GATEWAY_ADDR")
	if gw == "" {
		return "", 0
	}
	host, portstr, err := net.SplitHostPort(gw)
	if err != nil {
		log.FatalLog("Error in MEX_CRM_GATEWAY_ADDR format")
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.FatalLog("Error in MEX_CRM_GATEWAY_ADDR port format")
	}
	return host, port
}

func GetCloudletNetworkIfaceFile() string {
	return "/etc/network/interfaces.d/50-cloud-init.cfg"
}

// initMappedIPs takes the env var MEX_EXTERNAL_IP_MAP contents like:
// fromip1=toip1,fromip2=toip2 and populates mappedExternalIPs
func initMappedIPs() error {
	mappedExternalIPs = make(map[string]string)
	meip := os.Getenv("MEX_EXTERNAL_IP_MAP")
	if meip != "" {
		ippair := strings.Split(meip, ",")
		for _, i := range ippair {
			ia := strings.Split(i, "=")
			if len(ia) != 2 {
				return fmt.Errorf("invalid format for mapped ip, expect fromip=destip")
			}
			fromip := ia[0]
			toip := ia[1]
			mappedExternalIPs[fromip] = toip
		}

	}
	return nil
}

// GetMappedExternalIP returns the IP that the input IP should be mapped to. This
// is used for environments which used NATted external IPs
func GetMappedExternalIP(ip string) string {
	mappedip, ok := mappedExternalIPs[ip]
	if ok {
		return mappedip
	}
	return ip
}
