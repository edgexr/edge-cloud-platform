package mexos

//MetadataDetail has metadata
type MetadataDetail struct {
	Name          string `json:"name"`
	Tags          string `json:"tags"`
	Tenant        string `json:"tenant"`
	Region        string `json:"region"`
	Zone          string `json:"zone"`
	Location      string `json:"location"`
	Project       string `json:"project"`
	ResourceGroup string `json:"resourcegroup"`
	OpenRC        string `json:"openrc"`
	DNSZone       string `json:"dnszone"`
	Kind          string `json:"kind"`
	Operator      string `json:"operator"`
	Swarm         string `json:"swarm"`
}

//NetworkDetail has network data
type NetworkDetail struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	CIDR    string `json:"cidr"`
	Options string `json:"options"`
	Extra   string `json:"extra"`
}

//AgentDetail has data on agent
type AgentDetail struct {
	Image  string `json:"image"`
	Status string `json:"status"`
}

//FlavorDetail has data on flavor
type FlavorDetail struct {
	Name          string `json:"name"`
	Favorite      string `json:"favorite"`
	Memory        string `json:"memory"`
	Topology      string `json:"topology"`
	NodeFlavor    string `json:"nodeflavor"`
	MasterFlavor  string `json:"masterflavor"`
	NetworkScheme string `json:"networkscheme"`
	Storage       string `json:"storage"`
	StorageScheme string `json:"storagescheme"`
	CPUs          int    `json:"cpus"`
	Masters       int    `json:"masters"`
	Nodes         int    `json:"nodes"`
}

type FlavorDetailInfo struct {
	Name          string `json:"name"`
	Nodes         int    `json:"nodes"`
	Masters       int    `json:"masters"`
	NetworkScheme string `json:"networkscheme"`
	MasterFlavor  string `json:"masterflavor"`
	NodeFlavor    string `json:"nodeflavor"`
	StorageScheme string `json:"storagescheme"`
	Topology      string `json:"topology"`
}

type PortDetail struct {
	Name         string `json:"name"`
	MexProto     string `json:"mexproto"`
	Proto        string `json:"proto"`
	InternalPort int    `json:"internalport"`
	PublicPort   int    `json:"publicport"`
	PublicPath   string `json:"publicpath"`
}

//SpecDetail holds spec block
type SpecDetail struct {
	Flavor          string           `json:"flavor"` // appInst flavor?
	FlavorDetail    FlavorDetailInfo `json:"flavordetail"`
	Flags           string           `json:"flags"`
	RootLB          string           `json:"rootlb"`
	Image           string           `json:"image"`
	ImageFlavor     string           `json:"imageflavor"`
	ImageType       string           `json:"imagetype"`
	DockerRegistry  string           `json:"dockerregistry"`
	ExternalNetwork string           `json:"externalnetwork"`
	ExternalRouter  string           `json:"externalrouter"`
	Options         string           `json:"options"`
	ProxyPath       string           `json:"proxypath"`
	Ports           []PortDetail     `json:"ports"`
	Command         []string         `json:"command"`
	IPAccess        string           `json:"ipaccess"`
	URI             string           `json:"uri"`
	Key             string           `json:"key"`
	NetworkScheme   string           `json:"networkscheme"`
	Agent           AgentDetail      `json:"agent"`
}

type AppInstConfigDetail struct {
	Deployment string `json:"deployment"`
	Resources  string `json:"resources"`
	Template   string `json:"template"`
	Manifest   string `json:"manifest"`
	Base       string `json:"base"`
}

type AppInstConfig struct {
	Kind         string              `json:"kind"`
	Source       string              `json:"source"`
	ConfigDetail AppInstConfigDetail `json:"detail"`
}

type AgentValue struct {
	Image  string `json:"image"`
	Port   string `json:"port"`
	Status string `json:"status"`
}

type AppValue struct {
	Deployment string       `json:"deployment"`
	Name       string       `json:"name"`
	Kind       string       `json:"kind"`
	Manifest   string       `json:"manifest"`
	Image      string       `json:"image"`
	ImageType  string       `json:"imagetype"`
	ProxyPath  string       `json:"proxypath"`
	Template   string       `json:"template"`
	Base       string       `json:"base"`
	Overlay    string       `json:"overlay"`
	Ports      []PortDetail `json:"ports"`
}

type ClusterValue struct {
	Flavor   string `json:"flavor"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Zone     string `json:"zone"`
	Region   string `json:"region"`
	Location string `json:"location"`
	OSImage  string `json:"osimage"`
	Tenant   string `json:"tenant"`
	Swarm    string `json:"swarm"`
}

type StorageValue struct {
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
}

type EnvironmentValue struct {
	OpenRC string `json:"openrc"`
	MexEnv string `json:"mexenv"`
}

type NetworkValue struct {
	Router       string `json:"router"`
	Options      string `json:"options"`
	Name         string `json:"name"`
	External     string `json:"external"`
	IPAccess     string `json:"ipaccess"`
	SecurityRule string `json:"securityrule"`
	Scheme       string `json:"scheme"`
	DNSZone      string `json:"dnszone"`
	HolePunch    string `json:"holepunch"`
}

type OperatorValue struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type RegistryValue struct {
	Name   string `json:"name"`
	Docker string `json:"docker"`
	Update string `json:"update"`
}

type ResourceValue struct {
	Group   string `json:"group"`
	Project string `json:"project"`
}

type ValueDetail struct {
	Name        string           `json:"name"`
	Kind        string           `json:"kind"`
	Base        string           `json:"base"`
	Application AppValue         `json:"application"`
	Agent       AgentValue       `json:"agent"`
	Cluster     ClusterValue     `json:"cluster"`
	Network     NetworkValue     `json:"network"`
	Registry    RegistryValue    `json:"registry"`
	Operator    OperatorValue    `json:"operator"`
	Resource    ResourceValue    `json:"resource"`
	Environment EnvironmentValue `json:"environment"`
	VaultEnvMap map[string]string
}

type EnvData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VaultDataDetail struct {
	Env []EnvData `json:"env"`
}

type VaultData struct {
	Detail VaultDataDetail `json:"data"`
}

type VaultResponse struct {
	Data VaultData `json:"data"`
}

//Manifest is general container for the manifest yaml used by `mex`
type Manifest struct {
	Name       string         `json:"name"`
	APIVersion string         `json:"apiVersion"`
	Base       string         `json:"base"`
	Kind       string         `json:"kind"`
	Resource   string         `json:"resource"`
	Metadata   MetadataDetail `json:"metadata"`
	Spec       SpecDetail     `json:"spec"`
	Config     AppInstConfig  `json:"config"`
	Values     ValueDetail    `json:"values"`
}

type NetSpecInfo struct {
	Kind, Name, CIDR, Options string
	Extra                     []string
}
