package mexos

// This file stores a global cloudlet infra properties object. The long term solution is for the controller to send this via the
// notification channel when the cloudlet is provisioned.   The controller will do the vault access and pass this data down; this
// is a stepping stone to start using edgepro data strucures to hold info abou the cloudlet rather than custom types and so the vault
// is still directly accessed here as are env variable to populate some variables

import (
	"fmt"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var CloudletInfraCommon edgeproto.CloudletInfraCommon
var OpenstackProps edgeproto.OpenStackProperties

var MEXInfraVersion = "v2.0.0" //Stratus
var defaultOSImageName = "mobiledgex-" + MEXInfraVersion

func InitInfraCommon() error {
	mexEnvURL := os.Getenv("MEXENV_URL")
	if mexEnvURL == "" {
		return fmt.Errorf("Env variable MEXENV_URL not set")
	}
	openRcURL := os.Getenv("OPENRC_URL")
	err := InternVaultEnv(openRcURL, mexEnvURL)
	if err != nil {
		return fmt.Errorf("failed to InternVaultEnv: %v", err)
	}
	CloudletInfraCommon.CFKey = os.Getenv("MEX_CF_KEY")
	if CloudletInfraCommon.CFKey == "" {
		return fmt.Errorf("Env variable MEX_CF_KEY not set")
	}
	CloudletInfraCommon.CFUser = os.Getenv("MEX_CF_USER")
	if CloudletInfraCommon.CFKey == "" {
		return fmt.Errorf("Env variable MEX_CF_USER not set")
	}
	CloudletInfraCommon.DockerRegPass = os.Getenv("MEX_DOCKER_REG_PASS")
	if CloudletInfraCommon.DockerRegPass == "" {
		return fmt.Errorf("Env variable MEX_DOCKER_REG_PASS not set")
	}
	CloudletInfraCommon.DNSZone = "mobiledgex.net"
	CloudletInfraCommon.DockerRegistry = "registry.mobiledgex.net:5000"
	CloudletInfraCommon.RegistryFileServer = "registry.mobiledgex.net"
	return nil
}

func InitOpenstackProps() error {
	OpenstackProps.OpenRcVars = make(map[string]string)

	OpenstackProps.OSExternalNetworkName = os.Getenv("MEX_EXT_NETWORK")
	if OpenstackProps.OSExternalNetworkName == "" {
		OpenstackProps.OSExternalNetworkName = "external-network-shared"
	}

	OpenstackProps.OSImageName = os.Getenv("MEX_OS_IMAGE")
	if OpenstackProps.OSImageName == "" {
		OpenstackProps.OSImageName = defaultOSImageName
	}

	// defaulting some value
	OpenstackProps.OSExternalRouterName = os.Getenv("MEX_ROUTER")
	if OpenstackProps.OSExternalRouterName == "" {
		OpenstackProps.OSExternalRouterName = "mex-k8s-router-1"
	}
	OpenstackProps.OSMexNetwork = "mex-k8s-net-1"
	return nil
}

//GetCloudletExternalRouter returns default MEX external router name
func GetCloudletExternalRouter() string {
	//TODO validate existence and status
	return OpenstackProps.OSExternalRouterName
}

func GetCloudletExternalNetwork() string {
	// this will be unset if platform is not openstack
	// because InitOpenstackProps() will not have been called.
	return OpenstackProps.OSExternalNetworkName
}

// Utility functions that used to be within manifest.
//GetCloudletNetwork returns default MEX network, internal and prepped
func GetCloudletMexNetwork() string {
	//TODO validate existence and status
	return OpenstackProps.OSMexNetwork
}

func GetCloudletDNSZone() string {
	return CloudletInfraCommon.DNSZone
}

func GetCloudletNetworkScheme() string {
	return CloudletInfraCommon.NetworkScheme
}

func GetCloudletOSImage() string {
	return OpenstackProps.OSImageName
}

func GetCloudletAgentContainerImage() string {
	return "unused - unnecessary?"
	//return CloudletInfra.MexosContainerImageName
}

// todo: CRM supports only 1 registry
func GetCloudletDockerRegistry() string {
	return CloudletInfraCommon.DockerRegistry
}

func GetCloudletRegistryFileServer() string {
	return CloudletInfraCommon.RegistryFileServer
}

func GetCloudletCFKey() string {
	return CloudletInfraCommon.CFKey
}

func GetCloudletCFUser() string {
	return CloudletInfraCommon.CFUser
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
func GetCloudletUserData() string {
	return MEXDir() + "/userdata.txt"
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
