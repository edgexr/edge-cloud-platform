package mexosapi

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/limits"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/networks"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/images"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	log "github.com/sirupsen/logrus"
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
	insecure := os.Getenv("OS_INSECURE")
	caCert := os.Getenv("OS_CACERT")

	var provider *gophercloud.ProviderClient

	if caCert != "" {
		log.Debugf("CA CERT %s", caCert)
		config := &tls.Config{}
		if insecure != "" {
			log.Debugf("insecure skip true")
			config.InsecureSkipVerify = true
		}
		certpool := x509.NewCertPool()
		pem, pemerr := ioutil.ReadFile(caCert)
		if pemerr != nil {
			log.Debugf("cannot read error %v %v", caCert, pemerr)
			log.Error("Unable to read specified CA certificate(s)")
			return nil, pemerr
		}
		ok := certpool.AppendCertsFromPEM(pem)
		if !ok {
			err = fmt.Errorf("Ill-formed CA certificate(s) PEM file")
			log.Debugf("error %v", err)
			return nil, err
		}
		config.RootCAs = certpool
		transport := &http.Transport{TLSClientConfig: config, Proxy: http.ProxyFromEnvironment}
		provider, err = openstack.NewClient(authOpts.IdentityEndpoint)
		if err != nil {
			log.Debugf("error %v", err)
			return nil, err
		}
		provider.HTTPClient.Transport = transport
		err = openstack.Authenticate(provider, authOpts)
		if err != nil {
			log.Debugf("authentication error %v", err)
			return nil, err
		}
	} else {
		provider, err = openstack.AuthenticatedClient(authOpts)
		if err != nil {
			return nil, err
		}
	}

	log.Debugf("attempt to get client handle for region %s", region)
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
	if err != nil {
		return nil, err
	}
	log.Debugln("servers", actual)
	return actual, nil
}

//ListImages lists images from glance
func ListImages(client *gophercloud.ServiceClient, args *ImageListArgs) ([]images.Image, error) {
	allPages, err := images.ListDetail(client, images.ListOpts{}).AllPages()

	if err != nil {
		return nil, fmt.Errorf("can't list images, %v", err)
	}

	actual, err := images.ExtractImages(allPages)
	if err != nil {
		return nil, err
	}
	log.Debugln("images", actual)
	return actual, nil
}

//ListNetworks lists networks from neutron
func ListNetworks(client *gophercloud.ServiceClient) ([]networks.Network, error) {
	allPages, err := networks.List(client).AllPages()

	if err != nil {
		return nil, fmt.Errorf("can't list networks, %v", err)
	}

	actual, err := networks.ExtractNetworks(allPages)
	if err != nil {
		return nil, err
	}
	log.Debugln("networks", actual)
	return actual, nil
}

//ListFlavors lists flavors of hosted VM types
func ListFlavors(client *gophercloud.ServiceClient) ([]flavors.Flavor, error) {
	allPages, err := flavors.ListDetail(client, nil).AllPages()

	if err != nil {
		return nil, fmt.Errorf("can't list flavors, %v", err)
	}

	actual, err := flavors.ExtractFlavors(allPages)
	if err != nil {
		return nil, err
	}
	log.Debugln("flavors", actual)
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

	return err
}

// DeleteServer deletes a server identified by `id`.
func DeleteServer(client *gophercloud.ServiceClient, id string) error {
	res := servers.Delete(client, id)
	if res.Err != nil {
		return res.Err
	}

	return nil
}

//GetLimits returns platform project limits
func GetLimits(client *gophercloud.ServiceClient) (*limits.Limits, error) {
	res, err := limits.Get(client, nil).Extract()

	if err != nil {
		return nil, err
	}
	return res, nil
}
