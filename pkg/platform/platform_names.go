package platform

// Builtin platform names. These should only be referenced
// from platform-specific code. Platform independent code
// should base its logic off of the platform features.
// This is because additional platforms may be added with
// new names, but the platform-independent code must be able
// to handle new platforms without prior knowledge of their
// names.
const (
	PlatformTypeAWSEC2            = "awsec2"
	PlatformTypeAWSEKS            = "awseks"
	PlatformTypeAzure             = "azure"
	PlatformTypeDind              = "dind" // docker in docker
	PlatformTypeEdgebox           = "edgebox"
	PlatformTypeFake              = "fake"
	PlatformTypeFakeInfra         = "fakeinfra"
	PlatformTypeFakeEdgebox       = "fakeedgebox"
	PlatformTypeFakeSingleCluster = "fakesinglecluster"
	PlatformTypeFakeVMPool        = "fakevmpool"
	PlatformTypeFederation        = "federation"
	PlatformTypeGCP               = "gcp"
	PlatformTypeK8SBareMetal      = "k8sbaremetal"
	PlatformTypeK8SOperator       = "k8soperator"
	PlatformTypeKind              = "kind" // kubernetes in docker
	PlatformTypeKindInfra         = "kindinfra"
	PlatformTypeMock              = "mock"
	PlatformTypeOpenstack         = "openstack"
	PlatformTypeVCD               = "vcd"
	PlatformTypeVMPool            = "vmpool"
	PlatformTypeVSphere           = "vsphere"
)
