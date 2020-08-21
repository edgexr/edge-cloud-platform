package vmlayer

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// NetworkTypeVLAN is an OpenStack provider network type
const NetworkTypeVLAN string = "vlan"

// ServerIP is an IP address for a given network on a port.  In the case of floating IPs, there are both
// internal and external addresses which are associated via NAT.   In the non floating case, the external and internal are the same
type ServerIP struct {
	MacAddress             string
	InternalAddr           string // this is the address used inside the server
	ExternalAddr           string // this is external with respect to the server, not necessarily internet reachable.  Can be a floating IP
	Network                string
	PortName               string
	ExternalAddrIsFloating bool
}

type RouterDetail struct {
	Name       string
	ExternalIP string
}

type NetSpecInfo struct {
	CIDR                  string
	NetworkType           string
	NetworkAddress        string
	NetmaskBits           string
	Octets                []string
	MasterIPLastOctet     string
	DelimiterOctet        int // this is the X
	FloatingIPNet         string
	FloatingIPSubnet      string
	FloatingIPExternalNet string
	VnicType              string
	RouterGatewayIP       string
}

var SupportedSchemes = map[string]string{
	"name":             "Deprecated",
	"cidr":             "XXX.XXX.XXX.XXX/XX",
	"floatingipnet":    "Floating IP Network Name",
	"floatingipsubnet": "Floating IP Subnet Name",
	"floatingipextnet": "Floating IP External Network Name",
	"vnictype":         "VNIC Type",
	"routergateway":    "Router Gateway IP",
	"networktype":      "Network Type: " + NetworkTypeVLAN,
}

func GetSupportedSchemesStr() string {
	desc := []string{}
	for k, v := range SupportedSchemes {
		desc = append(desc, fmt.Sprintf("%s (%s)", k, v))
	}
	return fmt.Sprintf("Format: 'Name1=Value1,Name2=Value2,...';\nSupported Schemes: %s", strings.Join(desc, ", "))
}

//ParseNetSpec decodes netspec string
//TODO: IPv6
func ParseNetSpec(ctx context.Context, netSpec string) (*NetSpecInfo, error) {
	ni := &NetSpecInfo{}
	if netSpec == "" {
		return nil, fmt.Errorf("empty netspec")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "parsing netspec", "netspec", netSpec)
	items := strings.Split(netSpec, ",")
	for _, i := range items {
		kvs := strings.Split(i, "=")
		if len(kvs) != 2 {
			return nil, fmt.Errorf("incorrect netspec item format, expect key=value: %s", i)
		}
		k := strings.ToLower(kvs[0])
		v := kvs[1]

		if _, ok := SupportedSchemes[k]; !ok {
			return nil, fmt.Errorf("unknown netspec item key: %s", k)
		}

		switch k {
		case "name":
			log.SpanLog(ctx, log.DebugLevelInfra, "netspec name obsolete")
		case "cidr":
			ni.CIDR = v
		case "floatingipnet":
			ni.FloatingIPNet = v
		case "floatingipsubnet":
			ni.FloatingIPSubnet = v
		case "floatingipextnet":
			ni.FloatingIPExternalNet = v
		case "vnictype":
			ni.VnicType = v
		case "routergateway":
			ni.RouterGatewayIP = v
		case "networktype":
			ni.NetworkType = v
		default:
			return nil, fmt.Errorf("unknown netspec item key: %s", k)
		}
	}
	if ni.CIDR == "" {
		return nil, fmt.Errorf("Missing cidr=(value) in netspec")
	}
	sits := strings.Split(ni.CIDR, "/")
	if len(sits) < 2 {
		return nil, fmt.Errorf("invalid CIDR, no net mask")
	}
	ni.NetworkAddress = sits[0]
	ni.NetmaskBits = sits[1]

	ni.Octets = strings.Split(ni.NetworkAddress, ".")
	for i, it := range ni.Octets {
		if it == "X" {
			ni.DelimiterOctet = i
		}
	}
	if len(ni.Octets) != 4 {
		log.SpanLog(ctx, log.DebugLevelInfra, "invalid network address, wrong number of octets", "octets", ni.Octets)
		return nil, fmt.Errorf("invalid network address structure")
	}
	if ni.DelimiterOctet != 2 {
		log.SpanLog(ctx, log.DebugLevelInfra, "invalid network address, third octet must be X", "delimiterOctet", ni.DelimiterOctet)
		return nil, fmt.Errorf("invalid network address delimiter")
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "netspec info", "ni", ni, "items", items)
	return ni, nil
}

func GetAllowedClientCIDR() string {
	//XXX TODO get real list of allowed clients from remote database or template configuration
	return "0.0.0.0/0"
}

// serverIsNetplanEnabled checks for the existence of netplan, in which case there are no ifcfg files.  The current
// baseimage uses netplan, but CRM can still run on older rootLBs.
func ServerIsNetplanEnabled(ctx context.Context, client ssh.Client) bool {
	cmd := "netplan info"
	_, err := client.Output(cmd)
	return err == nil
}

func getNetplanContents(portName, ifName string, ipAddr string) string {
	return fmt.Sprintf(`## config for %s
network:
    version: 2
    ethernets:
        %s:
            dhcp4: no
            dhcp6: no
            addresses:
             - %s
`, portName, ifName, ipAddr)
}

// GetNetworkFileDetailsForIP returns interfaceFileName, fileMatchPattern, contents based on whether netplan is enabled
func GetNetworkFileDetailsForIP(ctx context.Context, portName string, ifName string, ipAddr string, netPlanEnabled bool) (string, string, string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNetworkFileDetailsForIP", "portName", portName, "ifName", ifName, "ipAddr", ipAddr, "netPlanEnabled", netPlanEnabled)
	fileName := "/etc/network/interfaces.d/" + portName + ".cfg"
	fileMatch := "/etc/network/interfaces.d/*-port.cfg"
	contents := fmt.Sprintf("auto %s\niface %s inet static\n   address %s/24", ifName, ifName, ipAddr)
	if netPlanEnabled {
		fileName = "/etc/netplan/" + portName + ".yaml"
		fileMatch = "/etc/netplan/*-port.yaml"
		contents = getNetplanContents(portName, ifName, ipAddr+"/24")
	}
	return fileName, fileMatch, contents
}

func (v *VMPlatform) AddRouteToServer(ctx context.Context, client ssh.Client, serverName string, cidr string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddRouteToServer", "serverName", serverName, "cidr", cidr)

	ni, err := ParseNetSpec(ctx, v.VMProperties.GetCloudletNetworkScheme())
	if err != nil {
		return err
	}
	if ni.FloatingIPNet != "" {
		// For now we do nothing when we have a floating IP because it means we are using the
		// openstack router to get everywhere anyway.
		log.SpanLog(ctx, log.DebugLevelInfra, "No route changes needed due to floating IP")
		return nil
	}

	ip, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("Invalid cidr for SetupVMRoute %s - %v", cidr, err)
	}
	maskStr := net.IP(netw.Mask)
	rtr := v.VMProperties.GetCloudletExternalRouter()
	gatewayIP := ni.RouterGatewayIP

	if gatewayIP == "" && rtr != NoConfigExternalRouter && rtr != NoExternalRouter {
		rd, err := v.VMProvider.GetRouterDetail(ctx, v.VMProperties.GetCloudletExternalRouter())
		if err != nil {
			return err
		}
		gatewayIP = rd.ExternalIP
	}

	if gatewayIP != "" {
		cmd := fmt.Sprintf("sudo ip route add %s via %s", netw.String(), gatewayIP)
		log.SpanLog(ctx, log.DebugLevelInfra, "Add route to network", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(out, "RTNETLINK") && strings.Contains(out, " exists") {
				log.SpanLog(ctx, log.DebugLevelInfra, "warning, can't add existing route to rootLB", "cmd", cmd, "out", out, "error", err)
			} else {
				return fmt.Errorf("can't add route to rootlb, %s, %s, %v", cmd, out, err)
			}
		}

		netplanEnabled := ServerIsNetplanEnabled(ctx, client)
		// make the route persist by adding the following line if not already present via grep.
		routeAddText := fmt.Sprintf("up route add -net %s netmask %s gw %s", ip, maskStr, gatewayIP)
		maskLen, _ := netw.Mask.Size()
		if netplanEnabled {
			routeAddText = fmt.Sprintf(`
            routes:
            - to: %s/%d
              via: %s`, ip, maskLen, gatewayIP)
		}
		interfacesFile := GetCloudletNetworkIfaceFile(netplanEnabled)
		cmd = fmt.Sprintf("grep -l '%s' %s", gatewayIP, interfacesFile)
		out, err = client.Output(cmd)
		if err != nil {
			// grep failed so not there already
			log.SpanLog(ctx, log.DebugLevelInfra, "adding route to interfaces file", "route", routeAddText, "file", interfacesFile)
			cmd = fmt.Sprintf("echo '%s'|sudo tee -a %s", routeAddText, interfacesFile)
			out, err = client.Output(cmd)
			if err != nil {
				return fmt.Errorf("can't add route to interfaces file: %v", err)
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "route already present in interfaces file", "file", interfacesFile)
		}
	}
	return nil
}

func (v *VMProperties) GetInternalNetworkRoute(ctx context.Context) (string, error) {
	netSpec, err := ParseNetSpec(ctx, v.GetCloudletNetworkScheme())
	if err != nil {
		return "", err
	}
	// cidr in netspec is format like 10.101.x.0/24, where X is the delimter octet.
	// Only the 3rd octet is supported for delimiter so the route is always /16
	netaddr := strings.ToUpper(netSpec.NetworkAddress)
	netaddr = strings.Replace(netaddr, "X", "0", 1)
	return netaddr + "/16", nil
}

// MaskLenToMask converts the number of bits in a mask
// to a dot notation mask
func MaskLenToMask(maskLen string) (string, error) {
	cidr := "255.255.255.255/" + maskLen
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	return ipnet.IP.String(), nil
}
