package mexos

// This file stores a global cloudlet infra properties object. The long term solution is for the controller to send this via the
// notification channel when the cloudlet is provisioned.   The controller will do the vault access and pass this data down; this
// is a stepping stone to start using edgepro data strucures to hold info abou the cloudlet rather than custom types and so the vault
// is still directly accessed here as are env variable to populate some variables

import (
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var CloudletInfra *edgeproto.CloudletInfraProperties
var CloudletInfraCommon *edgeproto.CloudletInfraCommon

//this is possible actions and optional parameters
var actionChoices = map[string]string{
	"CLOUDLET_KIND": "procname",
	"stop":          "procname",
	"status":        "procname",
	"ctrlapi":       "procname",
	"ctrlcli":       "procname",
	"ctrlinfo":      "procname",
	"dmeapi":        "procname",
	"deploy":        "",
	"cleanup":       "",
	"fetchlogs":     "",
	"createcluster": "",
	"deletecluster": "",
	"gencerts":      "",
	"cleancerts":    "",
	"sleep":         "seconds",
}

func InitializeCloudletInfra(fakecloudlet bool) error {
	log.DebugLog(log.DebugLevelMexos, "InitializeCloudletInfra called")

	CloudletInfra = new(edgeproto.CloudletInfraProperties)
	CloudletInfra.OpenstackProperties = new(edgeproto.OpenStackProperties)
	CloudletInfra.OpenstackProperties.OpenRcVars = make(map[string]string)
	CloudletInfra.AzureProperties = new(edgeproto.AzureProperties)
	CloudletInfra.GcpProperties = new(edgeproto.GcpProperties)
	CloudletInfraCommon = new(edgeproto.CloudletInfraCommon)

	var openRcURL string
	var mexEnvURL string

	if fakecloudlet {
		CloudletInfra.CloudletKind = cloudcommon.CloudletKindFake
	} else {

		CloudletInfra.CloudletKind = os.Getenv("CLOUDLET_KIND")
		if CloudletInfra.CloudletKind == "" {
			return fmt.Errorf("Env variable CLOUDLET_KIND not set")
		}
		mexEnvURL = os.Getenv("MEXENV_URL")
		if mexEnvURL == "" {
			return fmt.Errorf("Env variable MEXENV_URL not set")
		}

		openRcURL = os.Getenv("OPENRC_URL")
		if openRcURL == "" {
			return fmt.Errorf("Env variable OPENRC_URL not set")
		}

		err := InternVaultEnv(openRcURL, mexEnvURL, CloudletInfra)
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
	}

	switch CloudletInfra.CloudletKind {
	case cloudcommon.CloudletKindOpenStack:

		CloudletInfra.OpenstackProperties.OSExternalNetworkName = os.Getenv("MEX_EXT_NETWORK")
		if CloudletInfra.OpenstackProperties.OSExternalNetworkName == "" {
			CloudletInfra.OpenstackProperties.OSExternalNetworkName = "external-network-shared"
		}

		CloudletInfra.OpenstackProperties.OSImageName = os.Getenv("MEX_OS_IMAGE")
		if CloudletInfra.OpenstackProperties.OSImageName == "" {
			CloudletInfra.OpenstackProperties.OSImageName = "mobiledgex"
		}

		// defaulting some value
		CloudletInfra.OpenstackProperties.OSExternalRouterName = "mex-k8s-router-1"
		CloudletInfra.OpenstackProperties.OSMexNetwork = "mex-k8s-net-1"
		CloudletInfra.OpenstackProperties.OSNetworkScheme = "priv-subnet,mex-k8s-net-1,10.101.X.0/24"

	case cloudcommon.CloudletKindAzure:
		CloudletInfra.AzureProperties.Location = os.Getenv("MEX_AZURE_LOCATION")
		if CloudletInfra.AzureProperties.Location == "" {
			return fmt.Errorf("Env variable MEX_AZURE_LOCATION not set")
		}

		CloudletInfra.OpenstackProperties.OSImageName = os.Getenv("MEX_OS_IMAGE")
		if CloudletInfra.OpenstackProperties.OSImageName == "" {
			CloudletInfra.OpenstackProperties.OSImageName = "mobiledgex"
		}

	case cloudcommon.CloudletKindGCP:
		CloudletInfra.GcpProperties.Project = os.Getenv("MEX_GCP_PROJECT")
		if CloudletInfra.GcpProperties.Project == "" {
			//default
			CloudletInfra.OpenstackProperties.OSImageName = "still-entity-201400"
		}
		CloudletInfra.GcpProperties.Zone = os.Getenv("MEX_GCP_ZONE")
		if CloudletInfra.GcpProperties.Zone == "" {
			return fmt.Errorf("Env variable MEX_GCP_ZONE not set")
		}
	}
	// not supported yet but soon
	CloudletInfra.MexosContainerImageName = "not-supported"

	CloudletInfraCommon.DNSZone = "mobiledgex.net"
	CloudletInfraCommon.DockerRegistry = "registry.mobiledgex.net:5000"
	CloudletInfraCommon.RegistryFileServer = "registry.mobiledgex.net"

	log.DebugLog(log.DebugLevelMexos, "InitializeCloudletInfra done", "CloudletInfra", CloudletInfra)
	return nil
}

func CloudletIsLocalDIND() bool {
	return CloudletInfra.CloudletKind == cloudcommon.CloudletKindDIND
}

// returns true if kubectl can be run directly from the CRM rather than SSH jump thru LB
func CloudletIsDirectKubectlAccess() bool {
	return CloudletInfra.CloudletKind == cloudcommon.CloudletKindDIND ||
		CloudletInfra.CloudletKind == cloudcommon.CloudletKindAzure ||
		CloudletInfra.CloudletKind == cloudcommon.CloudletKindGCP
}

func GetCloudletKind() string {
	return CloudletInfra.CloudletKind
}

func GetCloudletAzureLocation() string {
	return CloudletInfra.AzureProperties.Location
}

func GetCloudletGCPProject() string {
	// default for now
	return CloudletInfra.GcpProperties.Project
}

func GetCloudletGCPZone() string {
	// default for now
	return CloudletInfra.GcpProperties.Zone
}

//GetCloudletExternalRouter returns default MEX external router name
func GetCloudletExternalRouter() string {
	//TODO validate existence and status
	return CloudletInfra.OpenstackProperties.OSExternalRouterName
}

func GetCloudletExternalNetwork() string {
	return CloudletInfra.OpenstackProperties.OSExternalNetworkName
}

// Utility functions that used to be within manifest.
//GetCloudletNetwork returns default MEX network, internal and prepped
func GetCloudletMexNetwork() string {
	//TODO validate existence and status
	return CloudletInfra.OpenstackProperties.OSMexNetwork
}

func GetCloudletDNSZone() string {
	return CloudletInfraCommon.DNSZone
}

func GetCloudletNetworkScheme() string {
	return CloudletInfra.OpenstackProperties.OSNetworkScheme
}

func GetCloudletOSImage() string {
	return CloudletInfra.OpenstackProperties.OSImageName
}

func GetCloudletAgentContainerImage() string {
	return CloudletInfra.MexosContainerImageName
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

// These not in the proto file yet because they may not change for a while
func GetCloudletTenant() string {
	return "null"
}
func GetCloudletUserData() string {
	return MEXDir() + "/userdata.txt"
}
func GetCloudletSecurityRule() string {
	return "default"
}
func GetCloudletMexosAgentPort() string {
	return "18889"
}
func GetCloudletRootLBFlavor() string {
	return "x1.medium"
}
