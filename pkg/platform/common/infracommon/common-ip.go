// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
