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

func (vp *VMProperties) AddRouteToServer(ctx context.Context, client ssh.Client, serverName, cidr, nextHop, interfaceName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddRouteToServer", "serverName", serverName, "cidr", cidr, "nextHop", nextHop, "interfaceName", interfaceName)

	ip, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("Invalid cidr for AddRouteToServer %s - %v", cidr, err)
	}
	if nextHop != "" {
		cmd := fmt.Sprintf("sudo ip route add %s via %s", netw.String(), nextHop)
		log.SpanLog(ctx, log.DebugLevelInfra, "Add route to network", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(out, "RTNETLINK") && strings.Contains(out, " exists") {
				log.SpanLog(ctx, log.DebugLevelInfra, "warning, can't add existing route to rootLB", "cmd", cmd, "out", out, "error", err)
			} else {
				return fmt.Errorf("can't add route to rootlb, %s, %s, %v", cmd, out, err)
			}
		}

		if !ServerIsNetplanEnabled(ctx, client) {
			// we no longer expect non-netplan enabled servers with our baseimage. Persisting routes has never been implemented properly
			// for non-netplan, so this should just fail
			return fmt.Errorf("Netplan not enabled on server: %s", serverName)
		}

		maskLen, _ := netw.Mask.Size()
		interfacesFile := GetCloudletNetworkIfaceFile()
		routeAddText := fmt.Sprintf(`
        %s:
            routes:
            - to: %s/%d
              via: %s`, interfaceName, ip, maskLen, nextHop)

		cmd = fmt.Sprintf("grep -l '%s' %s", nextHop, interfacesFile)
		out, err = client.Output(cmd)
		if err != nil {
			// grep failed so the route is not there already.
			// Append the new route addition and also the version is at the top after the network tag
			routeAddText = strings.ReplaceAll(routeAddText, "\n", "\\n")
			cmd = fmt.Sprintf("sudo sed -e '$ a\\ %s' -e '/version: 2/d' -e 's/^network:/network:\\n    version: 2/' -i %s ", routeAddText, interfacesFile)
			log.SpanLog(ctx, log.DebugLevelInfra, "Running sed to update interfaces file", "cmd", cmd)
			out, err = client.Output(cmd)
			if err != nil {
				return fmt.Errorf("Failed to update interfaces file: %s - %v", out, err)
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "Updated interfaces file", "out", out)
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
