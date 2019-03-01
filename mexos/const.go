package mexos

const APIversion = "v1"

const MEXSubnetSeed = 100
const MEXSubnetLimit = 250

const (
	k8smasterRole = "k8s-master"
	k8snodeRole   = "k8s-node"
)

//For netspec components
//  netType,netName,netCIDR,netOptions
const (
	NetTypeVal = 0
	NetNameVal = 1
	NetCIDRVal = 2
	NetOptVal  = 3
)

// 'Kind' strings for edgeproto.App.ConfigFile type
const (
	AppConfigHemYaml = "hemlCustomizationYaml"
	AppConfigK8sYaml = "k8sConfigurationYaml"
)
