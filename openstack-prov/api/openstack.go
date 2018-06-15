package mexosapi

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	log "github.com/bobbae/logrus"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/networks"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/images"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

//NovaArgs includes Openstack compute server parameters
type NovaArgs struct {
	Region, AvailabilityZone, Tenant string
	Name, Image, Flavor              string
	Network, FixedIP                 string
	Metadata                         map[string]string
	UserData                         []byte
	ConfigDrive                      *bool
}

//NovaListArgs contains argument parameters for Nova
type NovaListArgs struct {
	//TODO
}

//ImageListArgs contains options for listing images
type ImageListArgs struct {
	//TODO
}

//TODO multiple networks

//InternOSEnv internalizes openstack environment
func InternOSEnv(fn string) error {
	if _, err := os.Stat(fn); err != nil {
		return fmt.Errorf("invalid file %v, %v", fn, err)
	}

	inFile, _ := os.Open(fn)
	defer func() {
		if err := inFile.Close(); err != nil {
			log.Errorf("file close error, %v, %v\n", fn, err)
		}
	}()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		aline := scanner.Text()
		if aline == "" {
			continue
		}
		if strings.HasPrefix(aline, "#") {
			continue
		}
		ws := strings.Split(aline, " ")
		aline = ws[1]
		terms := strings.Split(aline, "=")
		if len(terms) != 2 {
			return fmt.Errorf("invalid line %s", aline)
		}
		if err := os.Setenv(terms[0], terms[1]); err != nil {
			return fmt.Errorf("can't set env var %s", aline)
		}
		log.Debugln("setenv", terms[0], terms[1])
	}
	return nil
}

//GetOSClient acquires Openstack environment
func GetOSClient(region string) (*gophercloud.ServiceClient, error) {
	authOpts, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		return nil, err
	}

	provider, err := openstack.AuthenticatedClient(authOpts)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewComputeV2(provider, gophercloud.EndpointOpts{
		Region: region,
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}

//ListServers get the list of VM instances
func ListServers(client *gophercloud.ServiceClient, args *NovaListArgs) ([]servers.Server, error) {
	//TODO pagination
	allPages, err := servers.List(client, servers.ListOpts{}).AllPages()

	if err != nil {
		return nil, fmt.Errorf("can't get list of servers, %v", err)
	}

	actual, err := servers.ExtractServers(allPages)
	return actual, nil
}

//ListImages lists images from glance
func ListImages(client *gophercloud.ServiceClient, args *ImageListArgs) ([]images.Image, error) {
	allPages, err := images.ListDetail(client, images.ListOpts{}).AllPages()

	if err != nil {
		return nil, fmt.Errorf("can't list images, %v", err)
	}

	actual, err := images.ExtractImages(allPages)
	return actual, nil
}

//ListNetworks lists networks from neutron
func ListNetworks(client *gophercloud.ServiceClient) ([]networks.Network, error) {
	allPages, err := networks.List(client).AllPages()

	if err != nil {
		return nil, fmt.Errorf("can't list networks, %v", err)
	}

	actual, err := networks.ExtractNetworks(allPages)
	return actual, nil
}

//ListFlavors lists flavors of hosted VM types
func ListFlavors(client *gophercloud.ServiceClient) ([]flavors.Flavor, error) {
	allPages, err := flavors.ListDetail(client, nil).AllPages()

	if err != nil {
		return nil, fmt.Errorf("can't list flavors, %v", err)
	}

	actual, err := flavors.ExtractFlavors(allPages)
	return actual, nil
}

// CreateServer creates a Nova VM instance
func CreateServer(client *gophercloud.ServiceClient, args *NovaArgs) error {
	_, err := servers.Create(client, servers.CreateOpts{
		Name:             args.Name + "." + args.Tenant + ".mobiledgex.com", // name.tenant-1.mobiledgex.com
		ImageRef:         args.Image,
		FlavorRef:        args.Flavor,
		UserData:         args.UserData,
		AvailabilityZone: args.AvailabilityZone,
		Metadata:         args.Metadata,
		ConfigDrive:      args.ConfigDrive,
		Networks: []servers.Network{
			servers.Network{
				UUID:    args.Network,
				FixedIP: args.FixedIP,
			},
		},
	}).Extract()

	if err != nil {
		return err
	}

	return nil
}

// DeleteServer deletes a server identified by `id`.
func DeleteServer(client *gophercloud.ServiceClient, id string) error {
	res := servers.Delete(client, id)
	if res.Err != nil {
		return res.Err
	}

	return nil
}
