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
	"fmt"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	yaml "github.com/mobiledgex/yaml/v2"
)

var heatCreate string = "CREATE"
var heatUpdate string = "UPDATE"
var heatDelete string = "DELETE"
var heatTest string = "TEST"

var VmGroupTemplate = `
heat_template_version: 2016-10-14
description: Create a group of VMs

{{- if .SkipInfraSpecificCheck}}

parameters:
  {{- range .FloatingIPs}}
  {{.ParamName}}:
    type: string
    description: ID of the floating ip address
  {{- end}}
{{- end}}

resources:
    {{- if and .AntiAffinitySpecified .AntiAffinityEnabledInCloudlet}}
    affinity_group:
        type: OS::Nova::ServerGroup
        properties:
            name: {{.GroupName}}
            policies: [anti-affinity]
    {{- end}}

    {{- range .Subnets}}
    {{.Name}}:
        type: OS::Neutron::Subnet
        properties:
            cidr: {{.CIDR}}
            network: {{.NetworkName}}
            gateway_ip: {{.GatewayIP}}
            enable_dhcp: {{.DHCPEnabled}}
            dns_nameservers:
               {{- range .DNSServers}}
                 - {{.}}
               {{- end}}
            name: 
                {{.Name}}
    {{- end}}
    
    {{- range .Ports}}
    {{.Name}}:
        type: OS::Neutron::Port
        properties:
            name: {{.Name}}
            network: {{.NetworkName}}
            {{- if .VnicType}}
            binding:vnic_type: {{.VnicType}}
            {{- end}}
            {{- if .FixedIPs}}
            fixed_ips:
            {{- range .FixedIPs}}
                {{- if .Subnet.Preexisting}}
                - subnet: {{.Subnet.Name}}
                {{- else}}
                - subnet: { get_resource: {{.Subnet.Name}} }
                {{- end}}
                {{- if .Address}}
                  ip_address:  {{.Address}}
                {{- end}}
            {{- end}}
            {{- end}}
            {{- if .SecurityGroups}}
            security_groups:
            {{- range .SecurityGroups}}
                {{- if .Preexisting}}
                - {{.Name}}
                {{- else}}
                - { get_resource: {{.Name}} }
                {{- end}}
            {{- end}}
            {{- else}}
            port_security_enabled: false
            {{- end}} 
    {{- end}}
    
    {{- range .RouterInterfaces}}
    {{.RouterName}}-interface:
        type: OS::Neutron::RouterInterface
        properties:
            router:  {{.RouterName}}
            port: { get_resource: {{.RouterPort.Name}} }
    {{- end}}
    
    {{- range .SecurityGroups}}
    {{.Name}}:
        type: OS::Neutron::SecurityGroup
        properties:
            name: {{.Name}}
            rules:
            {{- range .EgressRules}}
                - direction: egress
                {{- if .Protocol}}
                  protocol: {{.Protocol}}
                {{- end}}
                {{- if .RemoteCidr}}
                  remote_ip_prefix: {{.RemoteCidr}}
                {{- end}}
                {{- if .PortRangeMin}}
                  port_range_min: {{.PortRangeMin}}
                  port_range_max: {{.PortRangeMax}}
                {{- end}}
            {{- end}}
            {{- $RemoteCidr := .AccessPorts.RemoteCidr}}
            {{- range .AccessPorts.Ports}}
                - direction: ingress
                  remote_ip_prefix: {{$RemoteCidr}}
                  protocol: {{.Proto}}
                  port_range_min: {{.Port}}
                  port_range_max: {{.EndPort}}
            {{- end}}
    {{- end}}
    
    {{- range .VMs}}
    {{- range .Volumes}}
    {{.Name}}:
        type: OS::Cinder::Volume
        properties:
            {{- if .ImageName}}
            image: {{.ImageName}}
            {{- end}}
            name: {{.Name}}
            size: {{.Size}}
            {{- if .AvailabilityZone}}
            availability_zone: {{.AvailabilityZone}}
            {{- end}}
    {{- end}}
        
    {{.Name}}:
        type: OS::Nova::Server
        properties:
            name: {{.Name}}
            {{- if and $.AntiAffinitySpecified $.AntiAffinityEnabledInCloudlet}}
            scheduler_hints:
                group: {get_resource: affinity_group}
            {{- end}}
            networks:
                {{- range .Ports}}
                {{- if .Preexisting}}
                - port: {{.Name}}
                {{- else}}
                - port: { get_resource: {{.Name}} }
                {{- end}}
                {{- end}}
            {{- if .ComputeAvailabilityZone}}
            availability_zone: {{.ComputeAvailabilityZone}}
            {{- end}}
            {{- range .Volumes}}
            block_device_mapping:
                - device_name: {{.DeviceName}}
                  volume_id: { get_resource: {{.Name}} }
                  delete_on_termination: "false"
            {{- end}}
            {{- if .ImageName}}
            image: {{.ImageName}}
            {{- end}} 
            flavor: {{.FlavorName}}
            config_drive: true
            user_data_format: RAW
            user_data: |
{{.UserData}}
            {{- if .MetaData}}
            metadata:
{{.MetaData}}
            {{- end}}
    {{- end}}

    {{- if .SkipInfraSpecificCheck}}
    {{- range .FloatingIPs}}
    {{.Name}}:
        type: OS::Neutron::FloatingIPAssociation
        properties:
            floatingip_id: { get_param: {{.ParamName}} }
            {{- if .Port.Preexisting}}
            port_id: {{.Port.Name}} }
            {{- else}}
            port_id: { get_resource: {{.Port.Name}} }
            {{- end}}
    {{- end}}
    {{- else}}
    {{- range .FloatingIPs}}
    {{.Name}}:
        type: OS::Neutron::FloatingIPAssociation
        properties:
            floatingip_id: {{.FloatingIpId}}
            {{- if .Port.Preexisting}}
            port_id: {{.Port.Name}} }
            {{- else}}
            port_id: { get_resource: {{.Port.Name}} }
            {{- end}}
    {{- end}}
    {{- end}}
`

func reindent(str string, indent int) string {
	out := ""
	for _, v := range strings.Split(str, "\n") {
		out += strings.Repeat(" ", indent) + v + "\n"
	}
	return strings.TrimSuffix(out, "\n")
}

func reindent16(str string) string {
	return reindent(str, 16)
}

func (o *OpenstackPlatform) getFreeFloatingIpid(ctx context.Context, extNet string) (string, error) {
	fips, err := o.ListFloatingIPs(ctx, extNet)
	if err != nil {
		return "", fmt.Errorf("Unable to list floating IPs %v", err)
	}
	fipid := ""
	for _, f := range fips {
		if f.Port == "" && f.FloatingIPAddress != "" {
			fipid = f.ID
			break
		}
	}
	if fipid == "" {
		return "", fmt.Errorf("Unable to allocate a floating IP")
	}
	return fipid, nil
}

func (o *OpenstackPlatform) waitForStack(ctx context.Context, stackname string, action string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "waiting for stack", "name", stackname, "action", action)
	start := time.Now()
	for {
		time.Sleep(10 * time.Second)
		hd, err := o.getHeatStackDetail(ctx, stackname)
		if action == heatDelete && hd == nil {
			// it's gone
			return nil
		}
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Got Heat Stack detail", "detail", hd)
		updateCallback(edgeproto.UpdateStep, fmt.Sprintf("Heat Stack Status: %s", hd.StackStatus))

		switch hd.StackStatus {
		case action + "_COMPLETE":
			log.SpanLog(ctx, log.DebugLevelInfra, "Heat Stack succeeded", "action", action, "stackName", stackname)
			return nil
		case action + "_IN_PROGRESS":
			elapsed := time.Since(start)
			if elapsed >= (time.Minute * 20) {
				// this should not happen and indicates the stack is stuck somehow
				log.InfoLog("Heat stack taking too long", "status", hd.StackStatus, "elasped time", elapsed)
				return fmt.Errorf("Heat stack taking too long")
			}
			continue
		case action + "_FAILED":
			log.InfoLog("Heat Stack failed", "action", action, "stackName", stackname)
			return fmt.Errorf("Heat Stack failed: %s", hd.StackStatusReason)
		default:
			log.InfoLog("Unexpected Heat Stack status", "status", stackname)
			return fmt.Errorf("Stack create unexpected status: %s", hd.StackStatus)
		}
	}
}

func (o *OpenstackPlatform) createOrUpdateHeatStackFromTemplate(ctx context.Context, templateData interface{}, stackName string, templateString string, action string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "createHeatStackFromTemplate", "stackName", stackName, "action", action)

	if action == heatCreate {
		updateCallback(edgeproto.UpdateTask, "Creating Heat Stack for "+stackName)
	} else {
		updateCallback(edgeproto.UpdateTask, "Updating Heat Stack for "+stackName)
	}
	buf, err := infracommon.ExecTemplate(stackName, templateString, templateData)
	if err != nil {
		return err
	}
	filename := stackName + "-heat.yaml"
	err = infracommon.WriteTemplateFile(filename, buf)
	if err != nil {
		return fmt.Errorf("WriteTemplateFile failed: %s", err)
	}
	if action == heatTest {
		log.SpanLog(ctx, log.DebugLevelInfra, "test action only, no heat operation performed")

		return nil
	}
	if action == heatCreate {
		err = o.createHeatStack(ctx, filename, stackName)
	} else {
		err = o.updateHeatStack(ctx, filename, stackName)
	}
	if err != nil {
		return err
	}
	err = o.waitForStack(ctx, stackName, action, updateCallback)
	return err
}

// UpdateHeatStackFromTemplate fills the template from templateData and creates the stack
func (o *OpenstackPlatform) UpdateHeatStackFromTemplate(ctx context.Context, templateData interface{}, stackName, templateString string, updateCallback edgeproto.CacheUpdateCallback) error {
	return o.createOrUpdateHeatStackFromTemplate(ctx, templateData, stackName, templateString, heatUpdate, updateCallback)
}

// CreateHeatStackFromTemplate fills the template from templateData and creates the stack
func (o *OpenstackPlatform) CreateHeatStackFromTemplate(ctx context.Context, templateData interface{}, stackName, templateString string, updateCallback edgeproto.CacheUpdateCallback) error {
	return o.createOrUpdateHeatStackFromTemplate(ctx, templateData, stackName, templateString, heatCreate, updateCallback)
}

// HeatDeleteStack deletes the VM resources
func (o *OpenstackPlatform) HeatDeleteStack(ctx context.Context, stackName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting heat stack for stack", "stackName", stackName)
	err := o.deleteHeatStack(ctx, stackName)
	if err != nil {
		return err
	}
	return o.waitForStack(ctx, stackName, heatDelete, edgeproto.DummyUpdateCallback)
}

func GetUserDataFromOSResource(ctx context.Context, stackTemplate *OSHeatStackTemplate) (map[string]string, error) {
	vmsUserData := make(map[string]string)
	for resourceName, resource := range stackTemplate.Resources {
		if resource.Type != "OS::Nova::Server" {
			continue
		}
		userData, ok := resource.Properties["user_data"]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "missing user data", "resource", resource)
			continue
		}
		userDataStr, ok := userData.(string)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "invalid user data", "resource", resource)
			continue
		}
		vmsUserData[resourceName] = strings.TrimSpace(userDataStr)
	}
	return vmsUserData, nil
}

func IsUserDataSame(ctx context.Context, userdata1, userdata2 string) bool {
	log.SpanLog(ctx, log.DebugLevelInfra, "match user data")

	userdataarr1 := strings.Split(userdata1, "\n")
	userdataarr2 := strings.Split(userdata2, "\n")
	if len(userdataarr1) != len(userdataarr2) {
		log.SpanLog(ctx, log.DebugLevelInfra, "userdata length mismatch", "userdata1", userdata1, "userdata2", userdata2)
		return false
	}
	for ii := 0; ii < len(userdataarr1); ii++ {
		m1 := strings.TrimSpace(userdataarr1[ii])
		m2 := strings.TrimSpace(userdataarr2[ii])
		if m1 != m2 {
			log.SpanLog(ctx, log.DebugLevelInfra, "userdata mismatch", "match1", m1, "match2", m2)
			return false
		}
	}
	return true
}

func GetChefKeysFromOSResource(ctx context.Context, stackTemplate *OSHeatStackTemplate) (map[string]string, error) {
	chefClientKeys := make(map[string]string)
	for _, resource := range stackTemplate.Resources {
		if resource.Type != "OS::Nova::Server" {
			continue
		}
		userData, ok := resource.Properties["user_data"]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "missing user data", "resource", resource)
			continue
		}
		userDataStr, ok := userData.(string)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "invalid user data", "resource", resource)
			continue
		}
		out := strings.Replace(userDataStr, `\n`, "\n", -1)

		uObj := make(map[string]interface{})
		err := yaml.Unmarshal([]byte(out), &uObj)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal userdata %v, %v", userData, err)
		}
		cObj, ok := uObj["chef"]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "skip, missing chef", "userdata", userData)
			continue
		}
		if chefObj, ok := cObj.(map[string]interface{}); ok {
			nodeName, ok := chefObj["node_name"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid chef node name: %v", chefObj["node_name"])
			}
			cert, ok := chefObj["validation_cert"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid chef validation cert: %v", chefObj["validation_cert"])
			}
			chefClientKeys[nodeName] = strings.TrimSpace(cert)
		} else {
			return nil, fmt.Errorf("invalid chef config: %v", cObj)
		}
	}
	return chefClientKeys, nil
}

// populateParams fills in some details which cannot be done outside of heat
func (o *OpenstackPlatform) populateParams(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, action string) (*ReservedResources, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "populateParams", "VMGroupOrchestrationParams", VMGroupOrchestrationParams.GroupName, "action", action)

	// lock the resource reservations
	resourceLock.Lock()
	defer resourceLock.Unlock()
	var reserved ReservedResources

	usedCidrs := make(map[string]string)
	if VMGroupOrchestrationParams.Netspec == nil {
		return nil, fmt.Errorf("Netspec is nil")
	}
	masterIP := ""

	if len(VMGroupOrchestrationParams.Subnets) > 0 {
		currentSubnetName := ""
		if action != heatCreate {
			currentSubnetName = vmlayer.MexSubnetPrefix + VMGroupOrchestrationParams.GroupName
		}
		if action != heatTest && !VMGroupOrchestrationParams.SkipInfraSpecificCheck {
			sns, snserr := o.ListSubnets(ctx, o.VMProperties.GetCloudletMexNetwork())
			if snserr != nil {
				return nil, fmt.Errorf("can't get list of subnets for %s, %v", o.VMProperties.GetCloudletMexNetwork(), snserr)
			}
			for _, s := range sns {
				usedCidrs[s.Subnet] = s.Name
			}
		}

		// find an available subnet or the current subnet for update and delete
		for i, s := range VMGroupOrchestrationParams.Subnets {
			if s.CIDR != vmlayer.NextAvailableResource {
				// no need to compute the CIDR
				continue
			}
			found := false
			for octet := 0; octet <= 255; octet++ {
				subnet := fmt.Sprintf("%s.%s.%d.%d/%s", VMGroupOrchestrationParams.Netspec.Octets[0], VMGroupOrchestrationParams.Netspec.Octets[1], octet, 0, VMGroupOrchestrationParams.Netspec.NetmaskBits)
				// either look for an unused one (create) or the current one (update)
				newSubnet := action == heatCreate || action == heatTest
				if (newSubnet && usedCidrs[subnet] == "") || (!newSubnet && usedCidrs[subnet] == currentSubnetName) {
					resby, alreadyReserved := ReservedSubnets[subnet]
					if alreadyReserved {
						log.SpanLog(ctx, log.DebugLevelInfra, "subnet already reserved", "subnet", subnet, "resby", resby)
						continue
					}
					found = true
					reserved.Subnets = append(reserved.Subnets, subnet)
					VMGroupOrchestrationParams.Subnets[i].CIDR = subnet
					if !VMGroupOrchestrationParams.Subnets[i].SkipGateway {
						VMGroupOrchestrationParams.Subnets[i].GatewayIP = fmt.Sprintf("%s.%s.%d.%d", VMGroupOrchestrationParams.Netspec.Octets[0], VMGroupOrchestrationParams.Netspec.Octets[1], octet, 1)
					}
					VMGroupOrchestrationParams.Subnets[i].NodeIPPrefix = fmt.Sprintf("%s.%s.%d", VMGroupOrchestrationParams.Netspec.Octets[0], VMGroupOrchestrationParams.Netspec.Octets[1], octet)
					masterIP = fmt.Sprintf("%s.%s.%d.%d", VMGroupOrchestrationParams.Netspec.Octets[0], VMGroupOrchestrationParams.Netspec.Octets[1], octet, 10)
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("cannot find subnet cidr")
			}
		}

		// if there are last octets specified and not full IPs, build the full address
		for i, p := range VMGroupOrchestrationParams.Ports {
			if p.IsAdditionalExternalNetwork {
				// additional networks can be specified with the subnet name or the network name. If the subnet was specified, then
				// the network name needs to be replaced and subnet needs to be added to fixed ips
				sd, err := o.GetSubnetDetail(ctx, p.NetworkName)
				if err == nil {
					// subnet was provided
					subnetName := p.NetworkName
					VMGroupOrchestrationParams.Ports[i].NetworkName = sd.NetworkID
					fip := vmlayer.FixedIPOrchestrationParams{
						Subnet: vmlayer.NewResourceReference(subnetName, subnetName, true),
					}
					log.SpanLog(ctx, log.DebugLevelInfra, "replacing network for subnet", "port", p.Name, "network", sd.NetworkID, "fip", fip)
					VMGroupOrchestrationParams.Ports[i].FixedIPs = append(VMGroupOrchestrationParams.Ports[i].FixedIPs, fip)
				}
				continue
			}
			for j, f := range p.FixedIPs {
				log.SpanLog(ctx, log.DebugLevelInfra, "updating fixed ip", "fixedip", f)
				if f.Address == vmlayer.NextAvailableResource && f.LastIPOctet != 0 {
					log.SpanLog(ctx, log.DebugLevelInfra, "populating fixed ip based on subnet", "VMGroupOrchestrationParams", VMGroupOrchestrationParams)
					found := false
					for _, s := range VMGroupOrchestrationParams.Subnets {
						if s.Name == f.Subnet.Name {
							VMGroupOrchestrationParams.Ports[i].FixedIPs[j].Address = fmt.Sprintf("%s.%d", s.NodeIPPrefix, f.LastIPOctet)
							log.SpanLog(ctx, log.DebugLevelInfra, "populating fixed ip based on subnet", "port", p.Name, "address", VMGroupOrchestrationParams.Ports[i].FixedIPs[j].Address)
							found = true
							break
						}
					}
					if !found {
						return nil, fmt.Errorf("cannot find matching subnet for port: %s", p.Name)
					}
				}
			}
		}
	}

	// Get chef keys for existing VMs
	chefClientKeys := make(map[string]string)
	vmsUserData := make(map[string]string)
	if action == heatUpdate {
		stackTemplate, err := o.getHeatStackTemplateDetail(ctx, VMGroupOrchestrationParams.GroupName)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch heat stack template for %s: %v", VMGroupOrchestrationParams.GroupName, err)
		}
		chefClientKeys, err = GetChefKeysFromOSResource(ctx, stackTemplate)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to fetch chef keys", "err", err)
		}
		vmsUserData, err = GetUserDataFromOSResource(ctx, stackTemplate)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to fetch vms userdata", "err", err)
		}
	}

	// populate the user data
	for i, v := range VMGroupOrchestrationParams.VMs {
		VMGroupOrchestrationParams.VMs[i].MetaData = vmlayer.GetVMMetaData(v.Role, masterIP, reindent16)
		// Copy client keys from existing template in case of update
		if v.CloudConfigParams.ChefParams != nil && action == heatUpdate {
			if v.CloudConfigParams.ChefParams.ClientKey == "" {
				key, ok := chefClientKeys[v.CloudConfigParams.ChefParams.NodeName]
				if !ok || key == "" {
					return nil, fmt.Errorf("missing chef client key for %s", v.CloudConfigParams.ChefParams.NodeName)
				}
				v.CloudConfigParams.ChefParams.ClientKey = key
			}
		}
		userdata, err := vmlayer.GetVMUserData(v.Name, v.SharedVolume, v.DeploymentManifest, v.Command, &v.CloudConfigParams, reindent16)
		if err != nil {
			return nil, err
		}

		if v.Role == vmlayer.RoleMaster && action == heatUpdate {
			if masterUserData, ok := vmsUserData[v.Name]; ok {
				if !IsUserDataSame(ctx, masterUserData, userdata) {
					return nil, fmt.Errorf("Unable to update cluster instance as it will redeploy master node, hence will affect running app instances. Please delete and recreate the cluster instance")
				}
			}
		}
		VMGroupOrchestrationParams.VMs[i].UserData = userdata
	}

	// populate the floating ips
	for i, f := range VMGroupOrchestrationParams.FloatingIPs {
		log.SpanLog(ctx, log.DebugLevelInfra, "Floating ip specified", "fip", f)
		if VMGroupOrchestrationParams.SkipInfraSpecificCheck {
			// skip, as fip id will be taken as part of stack params
			break
		}
		if f.FloatingIpId == vmlayer.NextAvailableResource {
			var fipid string
			var err error
			if action == heatTest {
				fipid = "test-fip-id"
			} else {
				fipid, err = o.getFreeFloatingIpid(ctx, VMGroupOrchestrationParams.Netspec.FloatingIPExternalNet)
				if err != nil {
					return nil, err
				}
				resby, alreadyReserved := ReservedFloatingIPs[fipid]
				if alreadyReserved {
					log.SpanLog(ctx, log.DebugLevelInfra, "floating ip aleady reserved", "fipid", fipid, "resby", resby)
					continue
				}
				reserved.FloatingIpIds = append(reserved.FloatingIpIds, fipid)
			}
			VMGroupOrchestrationParams.FloatingIPs[i].FloatingIpId = fipid
		}
	}
	err := o.ReserveResourcesLocked(ctx, &reserved, VMGroupOrchestrationParams.GroupName)
	if err != nil {
		return nil, err
	}
	return &reserved, nil
}

func (o *OpenstackPlatform) HeatCreateVMs(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "HeatCreateVMs", "VMGroupOrchestrationParams", VMGroupOrchestrationParams)
	reservations, err := o.populateParams(ctx, VMGroupOrchestrationParams, heatCreate)
	if err != nil {
		return err
	}
	err = o.CreateHeatStackFromTemplate(ctx, VMGroupOrchestrationParams, VMGroupOrchestrationParams.GroupName, VmGroupTemplate, updateCallback)
	releaseErr := o.ReleaseReservations(ctx, reservations)
	if releaseErr != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "ReleaseReservations error", "reservations", reservations, "releaseErr", releaseErr)
	}
	return err

}

func (o *OpenstackPlatform) HeatUpdateVMs(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "HeatUpdateVMs", "VMGroupOrchestrationParams", VMGroupOrchestrationParams)
	reservations, err := o.populateParams(ctx, VMGroupOrchestrationParams, heatUpdate)
	if err != nil {
		return err
	}
	err = o.UpdateHeatStackFromTemplate(ctx, VMGroupOrchestrationParams, VMGroupOrchestrationParams.GroupName, VmGroupTemplate, updateCallback)
	releaseErr := o.ReleaseReservations(ctx, reservations)
	if releaseErr != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "ReleaseReservations error", "reservations", reservations, "releaseErr", releaseErr)
	}
	return err
}
