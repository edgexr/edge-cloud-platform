// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openstack

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

const ResourceNotFound string = "Could not find resource"
const DuplicateResourceFound string = "More than one resource exists"
const StackNotFound string = "Stack not found"

func (s *OpenstackPlatform) TimedOpenStackCommand(ctx context.Context, name string, a ...string) ([]byte, error) {
	parmstr := strings.Join(a, " ")
	start := time.Now()

	log.SpanLog(ctx, log.DebugLevelInfra, "OpenStack Command Start", "name", name, "parms", parmstr)
	newSh := infracommon.Sh(s.openRCVars)

	out, err := newSh.Command(name, a).CombinedOutput()
	if err != nil {
		log.InfoLog("Openstack command returned error", "parms", parmstr, "err", err, "out", string(out), "elapsed time", time.Since(start))
		return out, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "OpenStack Command Done", "parmstr", parmstr, "elapsed time", time.Since(start))
	return out, nil

}

// ListServers returns a map of servers keyed by name
func (s *OpenstackPlatform) ListServers(ctx context.Context) (map[string]OSServer, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get server list, %s, %v", out, err)
		return nil, err
	}
	var servers []OSServer
	var serverMap = make(map[string]OSServer)

	err = json.Unmarshal(out, &servers)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	for _, s := range servers {
		serverMap[s.Name] = s
	}
	return serverMap, nil
}

// ListPorts returns a list of ports
func (s *OpenstackPlatform) ListPorts(ctx context.Context) ([]OSPort, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "port", "list", "-f", "json")

	if err != nil {
		err = fmt.Errorf("cannot get port list, %s, %v", out, err)
		return nil, err
	}
	var ports []OSPort
	err = json.Unmarshal(out, &ports)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return ports, nil
}

//ListPortsServerNetwork returns ports for a particular server on a given network
func (s *OpenstackPlatform) ListPortsServerNetwork(ctx context.Context, server, network string) ([]OSPort, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "port", "list", "--server", server, "--network", network, "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get port list, %s, %v", out, err)
		return nil, err
	}
	var ports []OSPort
	err = json.Unmarshal(out, &ports)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "list ports", "server", server, "network", network, "ports", ports)
	return ports, nil
}

//ListPortsServerNetwork returns ports for a particular server on any network
func (s *OpenstackPlatform) ListPortsServer(ctx context.Context, server string) ([]OSPort, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "port", "list", "--server", server, "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get port list, %s, %v", out, err)
		return nil, err
	}
	var ports []OSPort
	err = json.Unmarshal(out, &ports)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "list ports", "server", server, "ports", ports)
	return ports, nil
}

//ListImages lists avilable images in glance
func (s *OpenstackPlatform) ListImages(ctx context.Context) ([]OSImage, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "image", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get image list, %s, %v", out, err)
		return nil, err
	}
	var images []OSImage
	err = json.Unmarshal(out, &images)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "list images", "images", images)
	return images, nil
}

//GetImageDetail show of a given image from Glance
func (s *OpenstackPlatform) GetImageDetail(ctx context.Context, name string) (*OSImageDetail, error) {
	out, err := s.TimedOpenStackCommand(
		ctx, "openstack", "image", "show", name, "-f", "json",
		"-c", "id",
		"-c", "status",
		"-c", "updated_at",
		"-c", "checksum",
		"-c", "disk_format",
	)
	if err != nil {
		err = fmt.Errorf("cannot get image Detail for %s, %s, %v", name, string(out), err)
		return nil, err
	}
	var imageDetail OSImageDetail
	err = json.Unmarshal(out, &imageDetail)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "show image Detail", "Detail", imageDetail)
	return &imageDetail, nil
}

// fetch tags + properties etc of all images for resource mapping
func (s *OpenstackPlatform) ListImagesDetail(ctx context.Context) ([]OSImageDetail, error) {
	var img_details []OSImageDetail
	images, err := s.ListImages(ctx)
	if err != nil {
		return nil, err
	}

	for _, image := range images {
		details, err := s.GetImageDetail(ctx, image.Name)
		if err == nil {
			img_details = append(img_details, *details)
		}
	}
	return img_details, err
}

//
//ListNetworks lists networks known to the platform. Some created by the operator, some by users.
func (s *OpenstackPlatform) ListNetworks(ctx context.Context) ([]OSNetwork, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "network", "list", "-f", "json")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "network list failed", "out", out)
		err = fmt.Errorf("cannot get network list, %s, %v", out, err)
		return nil, err
	}
	var networks []OSNetwork
	err = json.Unmarshal(out, &networks)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "list networks", "networks", networks)
	return networks, nil
}

func (o *OpenstackPlatform) GetNetworkList(ctx context.Context) ([]string, error) {
	var networks []string
	nl, err := o.ListNetworks(ctx)

	if err != nil {
		return nil, err
	}

	for _, n := range nl {
		networks = append(networks, n.Name)
	}
	return networks, nil
}

//ShowFlavor returns the details of a given flavor.
func (s *OpenstackPlatform) ShowFlavor(ctx context.Context, flavor string) (details OSFlavorDetail, err error) {

	var flav OSFlavorDetail
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "flavor", "show", flavor, "-f", "json")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "flavor show failed", "out", out)
		return flav, err
	}

	err = json.Unmarshal(out, &flav)
	if err != nil {
		return flav, err
	}
	return flav, nil
}

//ListFlavors lists flavors known to the platform.   The ones matching the flavorMatchPattern are returned
func (s *OpenstackPlatform) ListFlavors(ctx context.Context) ([]OSFlavorDetail, error) {
	flavorMatchPattern := s.VMProperties.GetCloudletFlavorMatchPattern()
	r, err := regexp.Compile(flavorMatchPattern)
	if err != nil {
		return nil, fmt.Errorf("Cannot compile flavor match pattern")
	}
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "flavor", "list", "--long", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get flavor list, %s, %v", out, err)
		return nil, err
	}
	var flavors []OSFlavorDetail
	var flavorsMatched []OSFlavorDetail

	err = json.Unmarshal(out, &flavors)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	for _, f := range flavors {
		if r.MatchString(f.Name) {
			flavorsMatched = append(flavorsMatched, f)
		}
	}
	return flavorsMatched, nil
}

func (s *OpenstackPlatform) ListAZones(ctx context.Context) ([]OSAZone, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "availability", "zone", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get availability zone list, %s, %v", out, err)
		return nil, err
	}
	var zones []OSAZone
	err = json.Unmarshal(out, &zones)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return zones, nil
}

func (s *OpenstackPlatform) ListFloatingIPs(ctx context.Context, network string) ([]OSFloatingIP, error) {
	var err error
	var out []byte
	if network == "" {
		out, err = s.TimedOpenStackCommand(ctx, "openstack", "floating", "ip", "list", "-f", "json")
	} else {
		out, err = s.TimedOpenStackCommand(ctx, "openstack", "floating", "ip", "list", "--network", network, "-f", "json")
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to list floating IPs: %s, %s - %v", network, out, err)
	}
	var fips []OSFloatingIP
	err = json.Unmarshal(out, &fips)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return fips, nil
}

//CreateServer instantiates a new server instance, which is a KVM instance based on a qcow2 image from glance
func (s *OpenstackPlatform) CreateServer(ctx context.Context, opts *OSServerOpt) error {
	args := []string{
		"server", "create",
		"--config-drive", "true", //XXX always
		"--image", opts.Image, "--flavor", opts.Flavor,
	}
	if opts.UserData != "" {
		args = append(args, "--user-data", opts.UserData)
	}
	for _, p := range opts.Properties {
		args = append(args, "--property", p)
		// `p` should be like: "key=value"
	}
	for _, n := range opts.NetIDs {
		args = append(args, "--nic", "net-id="+n)
		// `n` should be like: "public,v4-fixed-ip=172.24.4.201"
	}
	args = append(args, opts.Name)
	//TODO additional args
	iargs := make([]string, len(args))
	for i, v := range args {
		iargs[i] = v
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "creating server with args", "iargs", iargs)

	//log.SpanLog(ctx,log.DebugLevelInfra, "openstack create server", "opts", opts, "iargs", iargs)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", iargs...)
	if err != nil {
		err = fmt.Errorf("cannot create server, %v, '%s'", err, out)
		return err
	}
	return nil
}

// GetActiveServerDetails returns details of the KVM instance waiting for it to be ACTIVE
func (s *OpenstackPlatform) GetActiveServerDetails(ctx context.Context, name string) (*OSServerDetail, error) {
	active := false
	srvDetail := &OSServerDetail{}
	for i := 0; i < 10; i++ {
		out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", "show", "-f", "json", name)
		if err != nil {
			if strings.Contains(string(out), "No server with a name or ID") {
				err = fmt.Errorf("%s -- can't show server %s, %s, %v", vmlayer.ServerDoesNotExistError, name, out, err)
			}
			return nil, err
		}
		//fmt.Printf("%s\n", out)
		err = json.Unmarshal(out, srvDetail)
		if err != nil {
			err = fmt.Errorf("cannot unmarshal while getting server detail, %v", err)
			return nil, err
		}
		if srvDetail.Status == "ACTIVE" {
			active = true
			break
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "wait for server to become ACTIVE", "server detail", srvDetail)
		time.Sleep(30 * time.Second)
	}
	if !active {
		return nil, fmt.Errorf("while getting server detail, waited but server %s is too slow getting to active state", name)
	}
	//log.SpanLog(ctx,log.DebugLevelInfra, "server detail", "server detail", srvDetail)
	return srvDetail, nil
}

func (s *OpenstackPlatform) GetOpenstackServerDetails(ctx context.Context, name string) (*OSServerDetail, error) {
	srvDetail := &OSServerDetail{}
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", "show", "-f", "json", name)
	if err != nil {
		if strings.Contains(string(out), "No server with a name or ID") {
			err = fmt.Errorf("%s -- can't show server %s, %s, %v", vmlayer.ServerDoesNotExistError, name, out, err)
		}
		return nil, err
	}
	//fmt.Printf("%s\n", out)
	err = json.Unmarshal(out, srvDetail)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal while getting server detail, %v", err)
		return nil, err
	}
	return srvDetail, nil
}

// GetPortDetails gets details of the specified port
func (s *OpenstackPlatform) GetPortDetails(ctx context.Context, name string) (*OSPortDetail, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get port details", "name", name)
	portDetail := &OSPortDetail{}

	out, err := s.TimedOpenStackCommand(ctx, "openstack", "port", "show", name, "-f", "json")
	if err != nil {
		err = fmt.Errorf("can't get port detail for port: %s, %s, %v", name, out, err)
		return nil, err
	}
	err = json.Unmarshal(out, &portDetail)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "port unmarshal failed", "err", err)
		err = fmt.Errorf("can't unmarshal port, %v", err)
		return nil, err
	}
	return portDetail, nil
}

// AttachPortToServer attaches a port to a server
func (s *OpenstackPlatform) AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action vmlayer.ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer", "serverName", serverName, "portName", portName)

	if action != vmlayer.ActionCreate {
		return nil
	}
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", "add", "port", serverName, portName)
	if err != nil {
		if strings.Contains(string(out), "still in use") {
			// port already attached
			log.SpanLog(ctx, log.DebugLevelInfra, "port already attached", "serverName", serverName, "portName", portName, "out", out, "err", err)
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "can't attach port", "serverName", serverName, "portName", portName, "out", out, "err", err)
		err = fmt.Errorf("can't attach port: %s, %s, %v", portName, out, err)
		return err
	}
	return nil
}

// DetachPortFromServer removes a port from a server
func (s *OpenstackPlatform) DetachPortFromServer(ctx context.Context, serverName, subnetName string, portName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer", "serverName", serverName, "portName", portName)

	out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", "remove", "port", serverName, portName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "can't remove port", "serverName", serverName, "portName", portName, "out", out, "err", err)
		if strings.Contains(string(out), "No Port found") {
			// when ports are removed they are detached from any server they are connected to.
			log.SpanLog(ctx, log.DebugLevelInfra, "port is gone", "portName", portName)
			err = nil
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "can't remove port", "serverName", serverName, "portName", portName, "out", out, "err", err)
		}
		err = fmt.Errorf("can't detach port %s from server %s: %s, %v", portName, serverName, out, err)
		return err
	}
	return nil
}

//DeleteServer destroys a KVM instance
//  sometimes it is not possible to destroy. Like most things in Openstack, try again.
func (s *OpenstackPlatform) DeleteServer(ctx context.Context, id string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting server", "id", id)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", "delete", id)
	if err != nil {
		err = fmt.Errorf("can't delete server %s, %s, %v", id, out, err)
		return err
	}
	return nil
}

// CreateNetwork creates a network with a name.
func (s *OpenstackPlatform) CreateNetwork(ctx context.Context, name, netType, availabilityZone string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "creating network", "network", name, "netType", netType, "availabilityZone", availabilityZone)
	args := []string{"network", "create"}
	if netType != "" {
		args = append(args, []string{"--provider-network-type", netType}...)
	}
	if availabilityZone != "" {
		args = append(args, []string{"--availability-zone-hint", availabilityZone}...)
	}
	args = append(args, name)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", args...)
	if err != nil {
		err = fmt.Errorf("can't create network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//DeleteNetwork destroys a named network
//  Sometimes it will fail. Openstack will refuse if there are resources attached.
func (s *OpenstackPlatform) DeleteNetwork(ctx context.Context, name string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting network", "network", name)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "network", "delete", name)
	if err != nil {
		err = fmt.Errorf("can't delete network %s, %s, %v", name, out, err)
		return err
	}
	return nil
}

//CreateSubnet creates a subnet within a network. A subnet is assigned ranges. Optionally DHCP can be enabled.
func (s *OpenstackPlatform) CreateSubnet(ctx context.Context, netRange, networkName, gatewayAddr, subnetName string, dhcpEnable bool) error {
	var dhcpFlag string
	if dhcpEnable {
		dhcpFlag = "--dhcp"
	} else {
		dhcpFlag = "--no-dhcp"
	}
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "subnet", "create",
		"--subnet-range", netRange, // e.g. 10.101.101.0/24
		"--network", networkName, // mex-k8s-net-1
		dhcpFlag,
		"--gateway", gatewayAddr, // e.g. 10.101.101.1
		subnetName) // e.g. mex-k8s-subnet-1
	if err != nil {
		nerr := &NeutronErrorType{}
		if ix := strings.Index(string(out), `{"NeutronError":`); ix > 0 {
			neutronErr := out[ix:]
			if jerr := json.Unmarshal(neutronErr, nerr); jerr != nil {
				err = fmt.Errorf("can't create subnet %s, %s, %v, error while parsing neutron error, %v", subnetName, out, err, jerr)
				return err
			}
			if strings.Index(nerr.NeutronError.Message, "overlap") > 0 {
				sd, serr := s.GetSubnetDetail(ctx, subnetName)
				if serr != nil {
					return fmt.Errorf("cannot get subnet detail for %s, while fixing overlap error, %v", subnetName, serr)
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "create subnet, existing subnet detail", "subnet detail", sd)

				//XXX do more validation

				log.SpanLog(ctx, log.DebugLevelInfra, "create subnet, reusing existing subnet", "result", out, "error", err)
				return nil
			}
		}
		err = fmt.Errorf("can't create subnet %s, %s, %v", subnetName, out, err)
		return err
	}
	return nil
}

//DeleteSubnet deletes the subnet. If this fails, remove any attached resources, like router, and try again.
func (s *OpenstackPlatform) DeleteSubnet(ctx context.Context, subnetName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting subnet", "name", subnetName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "subnet", "delete", subnetName)
	if err != nil {
		err = fmt.Errorf("can't delete subnet %s, %s, %v", subnetName, out, err)
		return err
	}
	return nil
}

//CreateRouter creates new router. A router can be attached to network and subnets.
func (s *OpenstackPlatform) CreateRouter(ctx context.Context, routerName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "creating router", "name", routerName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "router", "create", routerName)
	if err != nil {
		err = fmt.Errorf("can't create router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//DeleteRouter removes the named router. The router needs to not be in use at the time of deletion.
func (s *OpenstackPlatform) DeleteRouter(ctx context.Context, routerName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting router", "name", routerName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "router", "delete", routerName)
	if err != nil {
		err = fmt.Errorf("can't delete router %s, %s, %v", routerName, out, err)
		return err
	}
	return nil
}

//SetRouter assigns the router to a particular network. The network needs to be attached to
// a real external network. This is intended only for routing to external network for now. No internal routers.
// Sometimes, oftentimes, it will fail if the network is not external.
func (s *OpenstackPlatform) SetRouter(ctx context.Context, routerName, networkName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setting router to network", "router", routerName, "network", networkName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "router", "set", routerName, "--external-gateway", networkName)
	if err != nil {
		err = fmt.Errorf("can't set router %s to %s, %s, %v", routerName, networkName, out, err)
		return err
	}
	return nil
}

//AddRouterSubnet will connect subnet to another network, possibly external, via a router
func (s *OpenstackPlatform) AddRouterSubnet(ctx context.Context, routerName, subnetName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "adding router to subnet", "router", routerName, "network", subnetName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "router", "add", "subnet", routerName, subnetName)
	if err != nil {
		err = fmt.Errorf("can't add router %s to subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//RemoveRouterSubnet is useful to remove the router from the subnet before deletion. Otherwise subnet cannot
//  be deleted.
func (s *OpenstackPlatform) RemoveRouterSubnet(ctx context.Context, routerName, subnetName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "removing subnet from router", "router", routerName, "subnet", subnetName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "router", "remove", "subnet", routerName, subnetName)
	if err != nil {
		err = fmt.Errorf("can't remove router %s from subnet %s, %s, %v", routerName, subnetName, out, err)
		return err
	}
	return nil
}

//ListSubnets returns a list of subnets available
func (s *OpenstackPlatform) ListSubnets(ctx context.Context, netName string) ([]OSSubnet, error) {
	var err error
	var out []byte
	if netName != "" {
		out, err = s.TimedOpenStackCommand(ctx, "openstack", "subnet", "list", "--network", netName, "-f", "json")
	} else {
		out, err = s.TimedOpenStackCommand(ctx, "openstack", "subnet", "list", "-f", "json")
	}
	if err != nil {
		err = fmt.Errorf("can't get a list of subnets, %s, %v", out, err)
		return nil, err
	}
	subnets := []OSSubnet{}
	err = json.Unmarshal(out, &subnets)
	if err != nil {
		err = fmt.Errorf("can't unmarshal subnets, %v", err)
		return nil, err
	}
	//log.SpanLog(ctx,log.DebugLevelInfra, "list subnets", "subnets", subnets)
	return subnets, nil
}

//ListProjects returns a list of projects we can see
func (s *OpenstackPlatform) ListProjects(ctx context.Context) ([]OSProject, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "project", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("can't get a list of projects, %s, %v", out, err)
		return nil, err
	}
	projects := []OSProject{}
	err = json.Unmarshal(out, &projects)
	if err != nil {
		err = fmt.Errorf("can't unmarshal projects, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "list projects", "projects", projects)
	return projects, nil
}

//ListRouters returns a list of routers available
func (s *OpenstackPlatform) ListRouters(ctx context.Context) ([]OSRouter, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "router", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("can't get a list of routers, %s, %v", out, err)
		return nil, err
	}
	routers := []OSRouter{}
	err = json.Unmarshal(out, &routers)
	if err != nil {
		err = fmt.Errorf("can't unmarshal routers, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "list routers", "routers", routers)
	return routers, nil
}

//GetRouterDetail returns details per router
func (s *OpenstackPlatform) GetOpenStackRouterDetail(ctx context.Context, routerName string) (*OSRouterDetail, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "router", "show", "-f", "json", routerName)
	if err != nil {
		err = fmt.Errorf("can't get router details for %s, %s, %v", routerName, out, err)
		return nil, err
	}
	routerDetail := &OSRouterDetail{}
	err = json.Unmarshal(out, routerDetail)
	if err != nil {
		err = fmt.Errorf("can't unmarshal router detail, %v", err)
		return nil, err
	}
	//log.SpanLog(ctx,log.DebugLevelInfra, "router detail", "router detail", routerDetail)
	return routerDetail, nil
}

//CreateServerImage snapshots running service into a qcow2 image
func (s *OpenstackPlatform) CreateServerImage(ctx context.Context, serverName, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "creating image snapshot from server", "server", serverName, "image", imageName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", "image", "create", serverName, "--name", imageName)
	if err != nil {
		err = fmt.Errorf("can't create image from %s into %s, %s, %v", serverName, imageName, out, err)
		return err
	}
	return nil
}

//CreateImage puts images into glance
func (s *OpenstackPlatform) CreateImage(ctx context.Context, imageName, fileName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "creating image in glance", "image", imageName, "fileName", fileName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "image", "create",
		imageName,
		"--disk-format", s.VMProperties.GetCloudletImageDiskFormat(),
		"--container-format", "bare",
		"--file", fileName)
	if err != nil {
		err = fmt.Errorf("can't create image in glance, %s, %s, %s, %v", imageName, fileName, out, err)
		return err
	}
	return nil
}

//CreateImageFromUrl downloads image from URL and then puts into glance
func (s *OpenstackPlatform) CreateImageFromUrl(ctx context.Context, imageName, imageUrl, md5Sum string) error {
	filePath, err := vmlayer.DownloadVMImage(ctx, s.VMProperties.CommonPf.PlatformConfig.AccessApi, imageName, imageUrl, md5Sum)
	if err != nil {
		return err
	}
	defer func() {
		// Stale file might be present if download fails/succeeds, deleting it
		if delerr := cloudcommon.DeleteFile(filePath); delerr != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "filePath", filePath)
		}
	}()
	err = s.CreateImage(ctx, imageName, filePath)
	if err != nil {
		return fmt.Errorf("error creating image %v", err)
	}
	return err
}

//SaveImage takes the image name available in glance, as a result of for example the above create image.
// It will then save that into a local file. The image transfer happens from glance into your own laptop
// or whatever.
// This can take a while, transferring all the data.
func (s *OpenstackPlatform) SaveImage(ctx context.Context, saveName, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "saving image", "save name", saveName, "image name", imageName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "image", "save", "--file", saveName, imageName)
	if err != nil {
		err = fmt.Errorf("can't save image from %s to file %s, %s, %v", imageName, saveName, out, err)
		return err
	}
	return nil
}

//DeleteImage deletes the named image from glance. Sometimes backing store is still busy and
// will refuse to honor the request. Like most things in Openstack, wait for a while and try
// again.
func (s *OpenstackPlatform) DeleteImage(ctx context.Context, folder, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting image", "name", imageName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "image", "delete", imageName)
	if err != nil {
		if strings.Contains(string(out), ResourceNotFound) {
			log.SpanLog(ctx, log.DebugLevelInfra, "image not found", "name", imageName)
			return nil
		} else {
			err = fmt.Errorf("can't delete image %s, %s, %v", imageName, out, err)
			return err
		}
	}
	return nil
}

//GetSubnetDetail returns details for the subnet. This is useful when getting router/gateway
//  IP for a given subnet.  The gateway info is used for creating a server.
//  Also useful in general, like other `detail` functions, to get the ID map for the name of subnet.
func (s *OpenstackPlatform) GetSubnetDetail(ctx context.Context, subnetName string) (*OSSubnetDetail, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "subnet", "show", "-f", "json", subnetName)
	if err != nil {
		err = fmt.Errorf("can't get subnet details for %s, %s, %v", subnetName, out, err)
		return nil, err
	}
	subnetDetail := &OSSubnetDetail{}
	err = json.Unmarshal(out, subnetDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal subnet detail, %v", err)
	}
	//log.SpanLog(ctx,log.DebugLevelInfra, "get subnet detail", "subnet detail", subnetDetail)
	return subnetDetail, nil
}

//GetNetworkDetail returns details about a network.  It is used, for example, by GetExternalGateway.
func (s *OpenstackPlatform) GetNetworkDetail(ctx context.Context, networkName string) (*OSNetworkDetail, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "network", "show", "-f", "json", networkName)
	if err != nil {
		err = fmt.Errorf("can't get details for network %s, %s, %v", networkName, out, err)
		return nil, err
	}
	networkDetail := &OSNetworkDetail{}
	err = json.Unmarshal(out, networkDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal network detail, %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "get network detail", "network detail", networkDetail)
	return networkDetail, nil
}

//SetServerProperty sets properties for the server
func (s *OpenstackPlatform) SetServerProperty(ctx context.Context, name, property string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if property == "" {
		return fmt.Errorf("empty property")
	}
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", "set", "--property", property, name)
	if err != nil {
		return fmt.Errorf("can't set property %s on server %s, %s, %v", property, name, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "set server property", "name", name, "property", property)
	return nil
}

// createHeatStack creates a stack with the given template
func (s *OpenstackPlatform) createHeatStack(ctx context.Context, templateFile string, stackName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "create heat stack", "template", templateFile, "stackName", stackName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "stack", "create", "--template", templateFile, stackName)
	if err != nil {
		return fmt.Errorf("error creating heat stack: %s, %s -- %v", templateFile, string(out), err)
	}
	return nil
}

func (s *OpenstackPlatform) updateHeatStack(ctx context.Context, templateFile string, stackName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "update heat stack", "template", templateFile, "stackName", stackName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "stack", "update", "--template", templateFile, stackName)
	if err != nil {
		return fmt.Errorf("error udpating heat stack: %s -- %s, %v", templateFile, out, err)
	}
	return nil
}

// deleteHeatStack delete a stack with the given name
func (s *OpenstackPlatform) deleteHeatStack(ctx context.Context, stackName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "delete heat stack", "stackName", stackName)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "stack", "delete", stackName)
	if err != nil {
		if strings.Contains(string(out), StackNotFound) {
			log.SpanLog(ctx, log.DebugLevelInfra, "stack not found", "stackName", stackName)
			return fmt.Errorf(vmlayer.ServerDoesNotExistError)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "stack deletion failed", "stackName", stackName, "out", string(out), "err", err)
		return fmt.Errorf("stack deletion failed: %s, %s %v", stackName, out, err)
	}
	return nil
}

// getHeatStackDetail gets details of the provided stack
func (s *OpenstackPlatform) getHeatStackDetail(ctx context.Context, stackName string) (*OSHeatStackDetail, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "stack", "show", "-f", "json", stackName)
	if err != nil {
		err = fmt.Errorf("can't get stack details for %s, %s, %v", stackName, out, err)
		return nil, err
	}
	stackDetail := &OSHeatStackDetail{}
	err = json.Unmarshal(out, stackDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal stack detail, %v", err)
	}
	return stackDetail, nil
}

// getHeatStackTemplateDetail gets details of the provided stack template
func (s *OpenstackPlatform) getHeatStackTemplateDetail(ctx context.Context, stackName string) (*OSHeatStackTemplate, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "stack", "template", "show", "-f", "json", stackName)
	if err != nil {
		err = fmt.Errorf("can't get stack template details for %s, %s, %v", stackName, out, err)
		return nil, err
	}
	stackTemplateDetail := &OSHeatStackTemplate{}
	err = json.Unmarshal(out, stackTemplateDetail)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal stack template detail, %v", err)
	}
	return stackTemplateDetail, nil
}

// Get resource limits
func (s *OpenstackPlatform) OSGetLimits(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetLimits (Openstack) - Resources info & Supported flavors")
	var limits []OSLimit
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "limits", "show", "--absolute", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get limits from openstack, %s, %v", out, err)
		return err
	}
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	for _, l := range limits {
		if l.Name == "maxTotalRAMSize" {
			info.OsMaxRam = uint64(l.Value)
		} else if l.Name == "maxTotalCores" {
			info.OsMaxVcores = uint64(l.Value)
		} else if l.Name == "maxTotalVolumeGigabytes" {
			info.OsMaxVolGb = uint64(l.Value)
		}
	}

	finfo, _, _, err := s.GetFlavorInfo(ctx)
	if err != nil {
		return err
	}
	info.Flavors = finfo
	return nil
}

// GetNumberOfFloatingIps returns allocated,used
func (s *OpenstackPlatform) GetNumberOfFloatingIps(ctx context.Context) (int, int, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNumberOfFloatingIps")
	ns := s.VMProperties.GetCloudletNetworkScheme()
	nspec, err := vmlayer.ParseNetSpec(ctx, ns)
	if err != nil {
		return 0, 0, err
	}
	if nspec.FloatingIPExternalNet == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "no external floating ip external network")
		return 0, 0, nil
	}
	fipList, err := s.ListFloatingIPs(ctx, nspec.FloatingIPExternalNet)
	if err != nil {
		return 0, 0, err
	}
	allocated := len(fipList)
	used := 0
	for _, f := range fipList {
		if f.Port != "" {
			used++
		}
	}
	return allocated, used, nil
}

func (s *OpenstackPlatform) OSGetAllLimits(ctx context.Context) ([]OSLimit, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetLimits (Openstack) - Resources info and usage")
	var limits []OSLimit
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "limits", "show", "--absolute", "-f", "json")
	if err != nil {
		err = fmt.Errorf("cannot get limits from openstack, %s, %v", out, err)
		return nil, err
	}
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	// openstack has a bug in which maxTotalFloatingIps is always at 10 regardless of the actual quota and totalFloatingIpsUsed
	// always reads 0. Also, since we assume the floating IPs are pre-allocated the number in the pool is really
	// the restriction, not the quota.
	fipsAllocated, fipsUsed, err := s.GetNumberOfFloatingIps(ctx)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "substituting number of floating ips", "allocated", fipsAllocated, "used", fipsUsed)

	for i, l := range limits {
		if l.Name == "maxTotalFloatingIps" {
			limits[i].Value = fipsAllocated
		} else if l.Name == "totalFloatingIpsUsed" {
			limits[i].Value = fipsUsed
		}
	}
	return limits, nil
}

func (s *OpenstackPlatform) GetFlavorInfo(ctx context.Context) ([]*edgeproto.FlavorInfo, []OSAZone, []OSImage, error) {

	osflavors, err := s.ListFlavors(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get flavors, %v", err.Error())
	}
	if len(osflavors) == 0 {
		return nil, nil, nil, fmt.Errorf("no flavors found")
	}
	var finfo []*edgeproto.FlavorInfo
	for _, f := range osflavors {
		var props map[string]string
		if f.Properties != "" {
			props = ParseFlavorProperties(f)
		}

		finfo = append(
			finfo,
			&edgeproto.FlavorInfo{
				Name:    f.Name,
				Vcpus:   uint64(f.VCPUs),
				Ram:     uint64(f.RAM),
				Disk:    uint64(f.Disk),
				PropMap: props},
		)
	}
	zones, err := s.ListAZones(ctx)
	images, err := s.ListImages(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return finfo, zones, images, nil
}

func (o *OpenstackPlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	fl, _, _, err := o.GetFlavorInfo(ctx)
	return fl, err
}

func (s *OpenstackPlatform) OSGetConsoleUrl(ctx context.Context, serverName string) (*OSConsoleUrl, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get console url", "server", serverName)
	consoleType := s.GetConsoleType()
	if consoleType == "" {
		consoleType = "novnc"
	}
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "console", "url", "show", "-f", "json", "-c", "url", "--"+consoleType, serverName)
	if err != nil {
		err = fmt.Errorf("can't get console url details for %s, %s, %v", serverName, out, err)
		return nil, err
	}
	consoleUrl := &OSConsoleUrl{}
	err = json.Unmarshal(out, consoleUrl)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal console url output, %v", err)
	}
	return consoleUrl, nil
}

// Finds a resource by name by instance id.
// There are resources that are metered for instance-id, which are resources of their own
// The examples are instance_network_interface and instance_disk
// Openstack example call:
//   <openstack metric resource search --type instance_network_interface instance_id=dc32daa6-0d0a-4512-a9fa-2b989e913014>
// We only use the the first found result
func (s *OpenstackPlatform) OSFindResourceByInstId(ctx context.Context, resourceType, instId, name string) (*OSMetricResource, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "find resource for instance Id", "id", instId,
		"resource", resourceType)
	osRes := []OSMetricResource{}
	instArg := fmt.Sprintf("instance_id=%s", instId)
	queryArg := instArg
	// if resource name is specified - for example name of disk for an instance("vda") add this to the query
	if name != "" {
		queryArg = fmt.Sprintf("%s and name=%s", instArg, name)
	}
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "metric", "resource", "search",
		"-f", "json", "--type", resourceType, queryArg)
	if err != nil {
		err = fmt.Errorf("can't find resource %s, for %s, %s %v", resourceType, instId, out, err)
		return nil, err
	}
	err = json.Unmarshal(out, &osRes)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal Metric Resource, %v", err)
		return nil, err
	}
	if len(osRes) != 1 {
		return nil, fmt.Errorf("Unexpected Number of Meters found")
	}
	return &osRes[0], nil
}

// Get openstack metrics from ceilometer tsdb
// Example openstack call:
//   <openstack metric measures show --resource-id a9bf10cf-a709-5a47-8b69-da920b8f65cd network.incoming.bytes>
// This will return a range of measurements from the startTime
func (s *OpenstackPlatform) OSGetMetricsRangeForId(ctx context.Context, resId string, metric string, startTime time.Time) ([]OSMetricMeasurement, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get measure for Id", "id", resId, "metric", metric)
	measurements := []OSMetricMeasurement{}

	startStr := startTime.Format(time.RFC3339)

	out, err := s.TimedOpenStackCommand(ctx, "openstack", "metric", "measures", "show",
		"-f", "json", "--start", startStr, "--resource-id", resId, metric)
	if err != nil {
		err = fmt.Errorf("can't get measurements %s, for %s, %s %v", metric, resId, out, err)
		return []OSMetricMeasurement{}, err
	}
	err = json.Unmarshal(out, &measurements)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal measurements, %v", err)
		return []OSMetricMeasurement{}, err
	}
	// No value, means we don't need to write it
	if len(measurements) == 0 {
		return []OSMetricMeasurement{}, fmt.Errorf("No values for the metric")
	}
	return measurements, nil
}

func (o *OpenstackPlatform) GetCloudletImageSuffix(ctx context.Context) string {
	return ".qcow2"
}

// RemoveDuplicateImages is called when more than one image is found with the same name. This can happen in rare
// situations in which the an app was created twice at the same time on the same cloudlet (no longer possible due as this
// condition is now checked in PerformOrchestrationForVMApp), or if there are 2 cloudlets using the same openstack
// tenant (still possible in labs and PoC deployments)
// Cleanup logic is as follows:
// - The first "active" image found is retained
// - All images not in "active" state are removed. This could result in no images at all being left but at least
//   this is a recoverable situation
func (o *OpenstackPlatform) RemoveDuplicateImages(ctx context.Context, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveDuplicateImages", "imageName", imageName)

	imageIdsToDelete := []string{}
	imageToKeep := ""
	imageList, err := o.ListImages(ctx)
	if err != nil {
		return nil
	}
	for _, img := range imageList {
		if img.Name != imageName {
			continue
		}
		if img.Status != "active" {
			// delete images not active. If one is uploading, that process will just fail
			imageIdsToDelete = append(imageIdsToDelete, img.ID)
		} else {
			if imageToKeep == "" {
				imageToKeep = img.ID
			} else {
				// already have one good image, delete this one
				imageIdsToDelete = append(imageIdsToDelete, img.ID)
			}
		}
	}
	if imageToKeep == "" {
		return fmt.Errorf("no active image found for %s among duplicates, please try again", imageName)
	}
	for _, id := range imageIdsToDelete {
		err = o.DeleteImage(ctx, "", id)
		if err != nil {
			return fmt.Errorf("error deleting image id %s - %v", id, err)
		}
	}
	return nil
}

func (o *OpenstackPlatform) AddImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddImageIfNotPresent", "imageInfo", imageInfo)

	createImage := false
	imageFound := false
	imageDetail, err := o.GetImageDetail(ctx, imageInfo.LocalImageName)
	if err != nil {
		if strings.Contains(err.Error(), ResourceNotFound) {
			// Add image to Glance
			log.SpanLog(ctx, log.DebugLevelInfra, "image is not present in glance, add image")
			createImage = true
		} else if strings.Contains(err.Error(), DuplicateResourceFound) {
			err = o.RemoveDuplicateImages(ctx, imageInfo.LocalImageName)
			if err != nil {
				return err
			}
			// now that we have deleted all duplicates, get the image detail again
			imageDetail, err = o.GetImageDetail(ctx, imageInfo.LocalImageName)
			if err != nil {
				return err
			}
			imageFound = true
		} else {
			return err
		}
	} else {
		imageFound = true
	}
	if imageFound {
		if imageDetail.Status != "active" {
			return fmt.Errorf("image in store %s is not active", imageInfo.LocalImageName)
		}
		if imageDetail.Checksum != imageInfo.Md5sum {
			if imageInfo.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW && imageDetail.DiskFormat == vmlayer.ImageFormatVmdk {
				log.SpanLog(ctx, log.DebugLevelInfra, "image was imported as vmdk, checksum match not possible")
			} else {
				return fmt.Errorf("mismatch in md5sum for image in glance: %s", imageInfo.LocalImageName)
			}
		}
		glanceImageTime, err := time.Parse(time.RFC3339, imageDetail.UpdatedAt)
		if err != nil {
			return err
		}
		if !imageInfo.SourceImageTime.IsZero() {
			if imageInfo.SourceImageTime.Sub(glanceImageTime) > 0 {
				// Update the image in Glance
				updateCallback(edgeproto.UpdateTask, "Image in store is outdated, deleting old image")
				err = o.DeleteImage(ctx, "", imageInfo.LocalImageName)
				if err != nil {
					return err
				}
				createImage = true
			}
		}
	}
	if createImage {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Creating VM Image from URL: %s", imageInfo.LocalImageName))
		err = o.CreateImageFromUrl(ctx, imageInfo.LocalImageName, imageInfo.ImagePath, imageInfo.Md5sum)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *OpenstackPlatform) SetPowerState(ctx context.Context, serverName, serverAction string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setting server state", "serverName", serverName, "serverAction", serverAction)
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "server", serverAction, serverName)
	if err != nil {
		err = fmt.Errorf("unable to %s server %s, %s, %v", serverAction, serverName, out, err)
		return err
	}
	return nil
}
