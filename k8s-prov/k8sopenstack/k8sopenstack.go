package k8sopenstack

import (
	"fmt"
	"io/ioutil"
	"os"

	toml "github.com/bobbae/go-toml"
	log "github.com/bobbae/logrus"
	mexosapi "github.com/mobiledgex/edge-cloud-infra/openstack-prov/api"
	mexosagent "github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/api"
)

//DefaultSettings contains default parameters for use with a Openstack installation
type DefaultSettings struct {
	Region  string
	Zone    string
	Image   string
	Network string
	Flavor  string
}

//KubernetesSettings contains information for a kind of kubernetes cluster layout
type KubernetesSettings struct {
	NodeAddrs  []string
	NodeRoles  []string
	ProxyAddr  string
	MasterAddr string
}

//ConfigData holds both openstack Defaults and Kubernetes cluster settings
type ConfigData struct {
	Defaults   DefaultSettings
	Kubernetes KubernetesSettings
}

//Config holds k8sopenstack specific config data
var Config ConfigData

func init() {
	if err := initConfig(); err != nil {
		log.Fatalf("cannot init configuration, %v", err)
	}
	if err := initOSEnv(); err != nil {
		log.Fatalf("cannot init openstack environment, %v", err)
	}
}

func initOSEnv() error {
	osenv := os.Getenv("MEX_K8SOS_ENV")
	if osenv == "" {
		return fmt.Errorf("no MEX_K8SOS_ENV")
	}
	if !exists(osenv) {
		return fmt.Errorf("file %s does not exist", osenv)
	}
	err := mexosapi.InternOSEnv(osenv)
	if err != nil {
		return fmt.Errorf("cannot intern OS env from %s, %v", osenv, err)
	}
	return nil
}

func initConfig() error {
	config := os.Getenv("MEX_K8SOS_CONFIG")
	if config == "" {
		return fmt.Errorf("no MEX_K8SOS_CONFIG")
	}
	if !exists(config) {
		return fmt.Errorf("file %s does not exist", config)
	}

	err := readConfig(config)
	if err != nil {
		return fmt.Errorf("cannot read defaults from %s, %v", config, err)
	}
	return nil
}

func readConfig(fn string) error {
	dat, err := ioutil.ReadFile(fn)
	if err != nil {
		return fmt.Errorf("cannot read file %s, %v", fn, err)
	}

	//XXX allow json, yaml, ...
	if err := toml.Unmarshal(dat, &Config); err != nil {
		return fmt.Errorf("cannot unmarshal toml file %s, %v", fn, err)
	}
	log.Debugln("config", fn, Config)
	return nil
}

func exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			log.Debugf("file %s does not exist", name)
			return false
		}
	}
	return true
}

func readUserData() ([]byte, error) {
	userdata := os.Getenv("MEX_K8SOS_USERDATA")
	if userdata == "" {
		return nil, fmt.Errorf("no MEX_K8SOS_USERDATA")
	}
	if !exists(userdata) {
		return nil, fmt.Errorf("file %s doesn't exist", userdata)
	}

	dat, err := ioutil.ReadFile(userdata)
	if err != nil {
		return nil, fmt.Errorf("can't read file %s, %v", userdata, err)
	}
	if len(dat) < 1 {
		return nil, fmt.Errorf("userdata too short")
	}

	return dat, nil
}

//CreateKubernetesCluster creates a kubernetes cluster inside VM instances which
//are hosted by Openstack.
func CreateKubernetesCluster(req *mexosagent.Provision) error {
	var True bool
	True = true

	log.Debugln("request to create kubernetes cluster on openstack", req)

	if req.Kind != "kubernetes-mini-openstack" {
		return fmt.Errorf("invalid request of kind, %v", req.Kind)
	}
	//TODO support more deployment Kinds

	if req.Tenant == "" {
		return fmt.Errorf("missing tenant name")
	}

	if req.Name == "" {
		return fmt.Errorf("missing deployment name")
	}

	if req.Region == "" {
		req.Region = Config.Defaults.Region
	}

	if req.Zone == "" {
		req.Zone = Config.Defaults.Zone
	}

	client, err := mexosapi.GetOSClient(req.Region)
	if err != nil {
		return fmt.Errorf("cannot get client for region %s, %v", req.Region, err)
	}

	images, err := mexosapi.ListImages(client, &mexosapi.ImageListArgs{})

	if err != nil {
		return fmt.Errorf("can't list images, %v", err)
	}

	if req.Image == "" {
		req.Image = Config.Defaults.Image
	}

	var imageID string

	for _, img := range images {
		if img.Name == req.Image {
			imageID = img.ID
		}
	}

	log.Debugln("imageID", imageID)

	if imageID == "" {
		return fmt.Errorf("image not found, %v", req.Image)
	}

	if req.Network == "" {
		req.Network = Config.Defaults.Network
	}

	var networkID string

	networks, err := mexosapi.ListNetworks(client)

	if err != nil {
		return fmt.Errorf("can't list networks, %v", err)
	}

	for _, network := range networks {
		if network.Label == req.Network {
			networkID = network.ID
		}
	}

	if networkID == "" {
		return fmt.Errorf("network not found, %v", req.Network)
	}

	log.Debugln("networkID", networkID)

	if req.Flavor == "" {
		req.Flavor = Config.Defaults.Flavor
	}

	var flavorID string

	flavors, err := mexosapi.ListFlavors(client)

	if err != nil {
		return fmt.Errorf("can't list flavors, %v", err)
	}

	for _, flavor := range flavors {
		if flavor.Name == req.Flavor {
			flavorID = flavor.ID
		}
	}

	if flavorID == "" {
		return fmt.Errorf("cannot find flavor, %s", req.Flavor)
	}

	log.Debugln("flavorID", flavorID)

	dat, err := readUserData()
	if err != nil {
		return fmt.Errorf("cannot read userdata, %v", err)
	}

	for i := range Config.Kubernetes.NodeAddrs {
		args := mexosapi.NovaArgs{
			Region:           req.Region,
			AvailabilityZone: req.Zone,
			Tenant:           req.Tenant,
			Name:             req.Name, //multiple instances with the same names
			Image:            imageID,
			Flavor:           flavorID,
			Network:          networkID,
			UserData:         dat, //Auto converted to base64
			ConfigDrive:      &True,
		}

		args.Metadata = map[string]string{
			"edgeproxy": Config.Kubernetes.ProxyAddr,
			"role":      Config.Kubernetes.NodeRoles[i],
			"k8smaster": Config.Kubernetes.MasterAddr,
			"tenant":    req.Tenant, //XXX MEX Tenant vs. OS Tenant-ID
		}
		args.FixedIP = Config.Kubernetes.NodeAddrs[i]

		log.Debugln("userdata", string(dat))
		log.Debugln("client", client)

		err := mexosapi.CreateServer(client, &args)
		if err != nil {
			return fmt.Errorf("create server error, %v, %v", args, err)
		}
		log.Debugln("created server", args)

		if err != nil {
			return fmt.Errorf("failed to create server, %v, %v", args, err)
		}
	}
	return nil
}

//DeleteKubernetesCluster destroys the kubernetes cluster previously created via CreateKubernetesCluster()
func DeleteKubernetesCluster(req *mexosagent.Provision) error {
	log.Debugln("request to delete kubernetes cluster on openstack", req)

	if req.Kind != "kubernetes-mini-openstack" {
		return fmt.Errorf("invalid request of kind, %v", req.Kind)
	}

	if req.Region == "" {
		req.Region = Config.Defaults.Region
	}

	client, err := mexosapi.GetOSClient(req.Region)
	if err != nil {
		return fmt.Errorf("cannot get client for region, %s, %v", req.Region, err)
	}

	servers, err := mexosapi.ListServers(client, &mexosapi.NovaListArgs{})

	if err != nil {
		return fmt.Errorf("can't list servers, %v", err)
	}

	req.Name = req.Name + "." + req.Tenant + ".mobiledgex.com"
	for _, srv := range servers {
		if srv.Name != req.Name {
			continue
		}
		if srv.Metadata["tenant"] != req.Tenant { //redundant
			continue
		}
		err := mexosapi.DeleteServer(client, srv.ID)
		if err != nil {
			return fmt.Errorf("server delete failed for %v, %v", srv, err)
		}
		log.Debugln("server deleted ok", srv)
	}
	return nil
}
