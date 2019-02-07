package mexos

/*
type templateFill struct {
	Name, Kind, Flavor, Tags, Tenant, DNSZone                  string
	ImageFlavor, RootLB, Resource, ResourceKind, ResourceGroup string
	StorageSpec, NetworkScheme                                 string
	NodeFlavor, Operator, Key, Image, Options                  string
	ImageType, ProxyPath                                       string
	ExternalNetwork, Project                                   string
	ExternalRouter, Flags, IPAccess, Swarm                     string
	NumMasters, NumNodes                                       int
	Config                                                     templateConfig
	Command                                                    []string
	SpecPorts                                                  []PortDetail
}

type templateConfig struct {
	Base, Overlay, Deployment, Resources, Manifest, Template string
}

var yamlMEXCluster = `apiVersion: v1
kind: {{.ResourceKind}}
resource: {{.Resource}}
metadata:
  name: {{.Name}}
  tags: {{.Tags}}
  kind: {{.Kind}}
  tenant: {{.Tenant}}
  operator: {{.Operator}}
  project: {{.Project}}
  dnszone: {{.DNSZone}}
  swarm: {{.Swarm}}
  resourcegroup: {{.ResourceGroup}}
spec:
  flags: {{.Flags}}
  flavor: {{.Flavor}}
  key: {{.Key}}
  dockerregistry: registry.mobiledgex.net:5000
  rootlb: {{.RootLB}}
  networkscheme: {{.NetworkScheme}}
`

var yamlMEXFlavor = `apiVersion: v1
kind: {{.ResourceKind}}
resource: {{.Resource}}
metadata:
  name: {{.Name}}
  tags: {{.Tags}}
  kind: {{.Kind}}
spec:
  flags: {{.Flags}}
  flavor: {{.Name}}
  flavordetail:
     name: {{.Name}}
     nodes: {{.NumNodes}}
     masters: {{.NumMasters}}
     networkscheme: {{.NetworkScheme}}
     masterflavor: {{.MasterFlavor}}
     nodeflavor: {{.NodeFlavor}}
     storagescheme: {{.StorageSpec}}
     topology: {{.Topology}}
`

var yamlMEXPlatform = `apiVersion: v1
kind: {{.ResourceKind}}
resource: {{.Resource}}
metadata:
  kind: {{.Kind}}
  name: {{.Name}}
  tags: {{.Tags}}
  tenant: {{.Tenant}}
  openrc: ~/.mobiledgex/openrc
  dnszone: {{.DNSZone}}
  operator: {{.Operator}}
spec:
  flags: {{.Flags}}
  flavor: {{.Flavor}}
  rootlb: {{.RootLB}}
  key: {{.Key}}
  dockerregistry: registry.mobiledgex.net:5000
  externalnetwork: {{.ExternalNetwork}}
  networkscheme: {{.NetworkScheme}}
  externalrouter: {{.ExternalRouter}}
  options: {{.Options}}
`

var yamlMEXApp = `apiVersion: v1
kind: {{.ResourceKind}}
resource: {{.Resource}}
metadata:
  kind: {{.Kind}}
  name: {{.Name}}
  tags: {{.Tags}}
  tenant: {{.Tenant}}
  operator: {{.Operator}}
  dnszone: {{.DNSZone}}
config:
  kind:
  source:
  detail:
    resources: {{.Config.Resources}}
    deployment: {{.Config.Deployment}}
    manifest: {{.Config.Manifest}}
    template: {{.Config.Template}}
    base: {{.Config.Base}}
    overlay: {{.Config.Overlay}}
spec:
  flags: {{.Flags}}
  key: {{.Key}}
  rootlb: {{.RootLB}}
  image: {{.Image}}
  imagetype: {{.ImageType}}
  imageflavor: {{.ImageFlavor}}
  proxypath: {{.ProxyPath}}
  flavor: {{.Flavor}}
  ipaccess: {{.IPAccess}}
  networkscheme: {{.NetworkScheme}}
  ports:
{{- range .SpecPorts}}
  - {{.Name}}
    {{.MexProto}}
    {{.Proto}}
    {{.InternalPort}}
    {{.PublicPort}}
    {{.PublicPath}}
{{- end}}
  command:
{{- range .Command}}
  - {{.}}
{{- end}}
`

func fillPlatformTemplateCloudletKey(rootLB *MEXRootLB, cloudletKeyStr string) (*Manifest, error) {
	log.DebugLog(log.DebugLevelMexos, "fill template cloudletkeystr", "cloudletkeystr", cloudletKeyStr)


	log.DebugLog(log.DebugLevelMexos, "using external network", "extNet", GetCloudletExternalNetwork())
	meximage := os.Getenv("MEX_OS_IMAGE")
	if meximage == "" {
		return nil, fmt.Errorf("Env variable MEX_OS_IMAGE not set")
	}

	data := templateFill{
		ResourceKind:    "platform",
		Resource:        NormalizeName(clk.OperatorKey.Name),
		Name:            clk.Name,
		Tags:            clk.Name + "-tag",
		Key:             clk.Name + "-" + NormalizeName(clk.OperatorKey.Name),
		Flavor:          "x1.medium",
		Operator:        NormalizeName(clk.OperatorKey.Name),
		RootLB:          rootLB.Name,
		Kind:            "mex-platform",
		ExternalNetwork: GetCloudletExternalNetwork(),
		NetworkScheme:   GetCloudletNetworkScheme(),
		DNSZone:         GetCloudletDNSZone(),
		ExternalRouter:  GetCloudletExternalRouter(),
		Options:         "dhcp",
	}
	mf, err := templateUnmarshal(&data, yamlMEXPlatform)
	if err != nil {
		return nil, err
	}
	return mf, nil
}


func templateUnmarshal(data *templateFill, yamltext string) (*Manifest, error) {
	//log.DebugLog(log.DebugLevelMexos, "template unmarshal", "yamltext", string, "data", data)
	tmpl, err := template.New("mex").Parse(yamltext)
	if err != nil {
		return nil, fmt.Errorf("can't create template for, %v", err)
	}
	var outbuffer bytes.Buffer
	err = tmpl.Execute(&outbuffer, data)
	if err != nil {
		//log.DebugLog(log.DebugLevelMexos, "template data", "data", data)
		return nil, fmt.Errorf("can't execute template, %v", err)
	}
	mf := &Manifest{}
	err = yaml.Unmarshal(outbuffer.Bytes(), mf)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error yaml unmarshal, templated data")
		return nil, fmt.Errorf("can't unmarshal templated data, %v, %s", err, outbuffer.String())
	}
	return mf, nil
}

*/
