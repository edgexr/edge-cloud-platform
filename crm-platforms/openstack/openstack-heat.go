package openstack

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var heatStackLock sync.Mutex
var heatCreate string = "CREATE"
var heatUpdate string = "UPDATE"
var heatDelete string = "DELETE"
var heatTest string = "TEST"

var VmGroupTemplate = `
heat_template_version: 2016-10-14
description: Create a group of VMs

resources:
    {{- range .Subnets}}
    {{.Name}}:
        type: OS::Neutron::Subnet
        properties:
            cidr: {{.CIDR}}
            network: mex-k8s-net-1
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
                {{- if .EgressRestricted}}
                {{- range .EgressRules}}
                    - direction: egress
                      protocol: {{.Protocol}}
                    {{- if .RemoteCidr}}
                      remote_ip_prefix: {{.RemoteCidr}}
                    {{- end}}
                    {{- if .PortRangeMin}}
                      port_range_min: {{.PortRangeMin}}
                      port_range_max: {{.PortRangeMax}}
                    {{- end}}
                {{- end}}
                {{- else}}
                    - direction: egress
                {{- end}}
                {{- range .AccessPorts}}
                    - direction: ingress
                      remote_ip_prefix: 0.0.0.0/0
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
    
    {{- range .FloatingIPs}}
    {{.Name}}:
        type: OS::Neutron::FloatingIPAssociation
        properties:
            floatingip_id: {{.FloatingIpId.Name}}
            {{- if .Port.Preexisting}}
            port_id: {{.Port.Name}} }
            {{- else}}
            port_id: { get_resource: {{.Port.Name}} }
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

	var buf bytes.Buffer
	updateCallback(edgeproto.UpdateTask, "Creating Heat Stack for "+stackName)

	funcMap := template.FuncMap{
		"Indent": func(values ...interface{}) string {
			s := values[0].(string)
			l := 4
			if len(values) > 1 {
				l = values[1].(int)
			}
			var newStr []string
			for _, v := range strings.Split(string(s), "\n") {
				nV := fmt.Sprintf("%s%s", strings.Repeat(" ", l), v)
				newStr = append(newStr, nV)
			}
			return strings.Join(newStr, "\n")
		},
	}

	tmpl, err := template.New(stackName).Funcs(funcMap).Parse(templateString)
	if err != nil {
		// this is a bug
		log.WarnLog("template new failed", "templateString", templateString, "err", err)
		return fmt.Errorf("template new failed: %s", err)
	}
	err = tmpl.Execute(&buf, templateData)
	if err != nil {
		return fmt.Errorf("Template Execute Failed: %s", err)
	}
	filename := stackName + "-heat.yaml"
	err = infracommon.WriteTemplateFile(filename, &buf)
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

// populateParams fills in some details which cannot be done outside of heat
func (o *OpenstackPlatform) populateParams(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, action string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "populateParams", "VMGroupOrchestrationParams", VMGroupOrchestrationParams.GroupName, "action", action)

	usedCidrs := make(map[string]string)
	if VMGroupOrchestrationParams.Netspec == nil {
		return fmt.Errorf("Netspec is nil")
	}
	masterIP := ""

	if len(VMGroupOrchestrationParams.Subnets) > 0 {
		currentSubnetName := ""
		if action != heatCreate {
			currentSubnetName = vmlayer.MexSubnetPrefix + VMGroupOrchestrationParams.GroupName
		}
		var sns []OSSubnet
		var snserr error
		if action != heatTest {
			sns, snserr = o.ListSubnets(ctx, o.VMProperties.GetCloudletMexNetwork())
			if snserr != nil {
				return fmt.Errorf("can't get list of subnets for %s, %v", o.VMProperties.GetCloudletMexNetwork(), snserr)
			}
			for _, s := range sns {
				usedCidrs[s.Subnet] = s.Name
			}
		}

		//find an available subnet or the current subnet for update and delete
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
					found = true
					VMGroupOrchestrationParams.Subnets[i].CIDR = subnet
					VMGroupOrchestrationParams.Subnets[i].GatewayIP = fmt.Sprintf("%s.%s.%d.%d", VMGroupOrchestrationParams.Netspec.Octets[0], VMGroupOrchestrationParams.Netspec.Octets[1], octet, 1)
					VMGroupOrchestrationParams.Subnets[i].NodeIPPrefix = fmt.Sprintf("%s.%s.%d", VMGroupOrchestrationParams.Netspec.Octets[0], VMGroupOrchestrationParams.Netspec.Octets[1], octet)
					masterIP = fmt.Sprintf("%s.%s.%d.%d", VMGroupOrchestrationParams.Netspec.Octets[0], VMGroupOrchestrationParams.Netspec.Octets[1], octet, 10)
					break
				}
			}
			if !found {
				return fmt.Errorf("cannot find subnet cidr")
			}
		}

		// if there are last octets specified and not full IPs, build the full address
		for i, p := range VMGroupOrchestrationParams.Ports {
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
						return fmt.Errorf("cannot find matching subnet for port: %s", p.Name)
					}
				}
			}
		}
	}

	// populate the user data
	for i, v := range VMGroupOrchestrationParams.VMs {
		VMGroupOrchestrationParams.VMs[i].MetaData = vmlayer.GetVMMetaData(v.Role, masterIP, reindent16)
		VMGroupOrchestrationParams.VMs[i].UserData = vmlayer.GetVMUserData(v.SharedVolume, v.DNSServers, v.DeploymentManifest, v.Command, reindent16)
	}

	// populate the floating ips

	for i, f := range VMGroupOrchestrationParams.FloatingIPs {
		if f.FloatingIpId.Name == vmlayer.NextAvailableResource {
			var fipid string
			var err error
			if action == heatTest {
				fipid = "test-fip-id"
			} else {
				fipid, err = o.getFreeFloatingIpid(ctx, VMGroupOrchestrationParams.Netspec.FloatingIPExternalNet)
				if err != nil {
					return err
				}
			}
			VMGroupOrchestrationParams.FloatingIPs[i].FloatingIpId.Name = fipid
		}
	}

	return nil
}

func (o *OpenstackPlatform) HeatCreateVMs(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "HeatCreateVMs", "VMGroupOrchestrationParams", VMGroupOrchestrationParams)

	heatStackLock.Lock()
	defer heatStackLock.Unlock()

	// populate parameters which cannot be done in advance
	err := o.populateParams(ctx, VMGroupOrchestrationParams, heatCreate)
	if err != nil {
		return err
	}
	return o.CreateHeatStackFromTemplate(ctx, VMGroupOrchestrationParams, VMGroupOrchestrationParams.GroupName, VmGroupTemplate, updateCallback)
}

func (o *OpenstackPlatform) HeatUpdateVMs(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "HeatUpdateVMs", "VMGroupOrchestrationParams", VMGroupOrchestrationParams)

	heatStackLock.Lock()
	defer heatStackLock.Unlock()

	err := o.populateParams(ctx, VMGroupOrchestrationParams, heatUpdate)
	if err != nil {
		return err
	}

	return o.UpdateHeatStackFromTemplate(ctx, VMGroupOrchestrationParams, VMGroupOrchestrationParams.GroupName, VmGroupTemplate, updateCallback)
}
