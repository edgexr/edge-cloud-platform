package mexos

// This file stores a global cloudlet infra properties object. The long term solution is for the controller to send this via the
// notification channel when the cloudlet is provisioned.   The controller will do the vault access and pass this data down; this
// is a stepping stone to start using edgepro data strucures to hold info abou the cloudlet rather than custom types and so the vault
// is still directly accessed here as are env variable to populate some variables

import (
	"fmt"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/deploygen"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var CloudletInfraCommon edgeproto.CloudletInfraCommon
var OpenstackProps edgeproto.OpenStackProperties

var MEXInfraVersion = "v2.0.2" //Stratus
var defaultOSImageName = "mobiledgex-" + MEXInfraVersion

func getVaultCloudletPath(filePath, vaultAddr string) string {
	return fmt.Sprintf(
		"https://%s/v1/secret/data/cloudlet/openstack/%s",
		vaultAddr, filePath,
	)
}

func InitInfraCommon(vaultAddr string) error {
	if vaultAddr == "" {
		return fmt.Errorf("vaultAddr is not specified")
	}
	mexEnvURL := getVaultCloudletPath("mexenv.json", vaultAddr)
	err := InternVaultEnv(mexEnvURL)
	if err != nil {
		return fmt.Errorf("failed to InternVaultEnv %s: %v", mexEnvURL, err)
	}
	CloudletInfraCommon.CfKey = os.Getenv("MEX_CF_KEY")
	if CloudletInfraCommon.CfKey == "" {
		return fmt.Errorf("Env variable MEX_CF_KEY not set")
	}
	CloudletInfraCommon.CfUser = os.Getenv("MEX_CF_USER")
	if CloudletInfraCommon.CfKey == "" {
		return fmt.Errorf("Env variable MEX_CF_USER not set")
	}
	CloudletInfraCommon.DockerRegPass = os.Getenv("MEX_DOCKER_REG_PASS")
	if CloudletInfraCommon.DockerRegPass == "" {
		return fmt.Errorf("Env variable MEX_DOCKER_REG_PASS not set")
	}
	CloudletInfraCommon.DnsZone = "mobiledgex.net"
	CloudletInfraCommon.DockerRegistry = deploygen.MexRegistry
	CloudletInfraCommon.DockerRegistrySecret = deploygen.MexRegistrySecret

	CloudletInfraCommon.RegistryFileServer = "registry.mobiledgex.net"
	return nil
}

func InitOpenstackProps(operatorName, physicalName, vaultAddr string) error {
	openRcURL := getVaultCloudletPath(physicalName+"/openrc.json", vaultAddr)
	err := InternVaultEnv(openRcURL)
	if err != nil {
		return fmt.Errorf("failed to InternVaultEnv %s: %v", openRcURL, err)
	}
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

func GetCloudletDockerRegistry() string {
	return CloudletInfraCommon.DockerRegistry
}

func GetCloudletDockerRegistrySecret() string {
	return CloudletInfraCommon.DockerRegistrySecret
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

func GetCloudletDockerPass() string {
	return CloudletInfraCommon.DockerRegPass
}

// GetCleanupOnFailure should be true unless we want to debug the failure,
// in which case this env var can be set to no.  We could consider making
// this configurable at the controller but really is only needed for debugging.
func GetCleanupOnFailure() bool {
	cleanup := os.Getenv("CLEANUP_ON_FAILURE")
	log.DebugLog(log.DebugLevelMexos, "GetCleanupOnFailure", "cleanup", cleanup)
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
