package infracommon

import (
	"fmt"
	"net/netip"
)

const (
	NumIPTypes = 2
	IndexIPV4  = 0
	IndexIPV6  = 1
)

func IPIndexOf(ipType IPVersion) int {
	switch ipType {
	case IPV4:
		return IndexIPV4
	case IPV6:
		return IndexIPV6
	}
	return 0
}

// IPs is a fixed length array of IP addresses based on type.
type IPs [NumIPTypes]string

// NetIPs is a fixed length array of IP addresses based on type.
type NetIPs [NumIPTypes]netip.Addr

func (s IPs) IsSet() bool {
	return s[0] != "" || s[1] != ""
}

func (s IPs) Matches(z IPs) bool {
	return s[0] == z[0] && s[1] == z[1]
}

func (s IPs) Sanitize(sanitizeFunc func(string) string) IPs {
	return IPs{
		sanitizeFunc(s[0]),
		sanitizeFunc(s[1]),
	}
}

func (s IPs) IPV4() string {
	return s[IndexIPV4]
}

func (s IPs) IPV6() string {
	return s[IndexIPV6]
}

func (s IPs) NetIPs() (NetIPs, error) {
	netIPs := NetIPs{}
	for ii, ip := range s {
		netip, err := netip.ParseAddr(ip)
		if err != nil {
			return netIPs, fmt.Errorf("failed to parse address %s, %s", ip, err)
		}
		netIPs[ii] = netip
	}
	return netIPs, nil
}
