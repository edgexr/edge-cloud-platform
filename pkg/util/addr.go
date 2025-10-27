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

package util

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// Get the external address with port when running under kubernetes.
// This allows horizontally scaled instances to talk to each other within
// a given k8s cluster.
func GetExternalApiAddr(defaultApiAddr string) (string, error) {
	if defaultApiAddr == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(defaultApiAddr)
	if err != nil {
		return "", fmt.Errorf("failed to parse api addr %s, %v", defaultApiAddr, err)
	}
	if host == "0.0.0.0" {
		addr, err := ResolveExternalAddr()
		if err == nil {
			defaultApiAddr = addr + ":" + port
		}
	}
	return defaultApiAddr, nil
}

// This is for figuring out the "external" address when
// running under kubernetes, which is really the internal CNI
// address that containers can use to talk to each other.
func ResolveExternalAddr() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}

func TrimScheme(addr string) string {
	idx := strings.Index(addr, "://")
	if idx == -1 {
		return addr
	}
	return addr[idx+3:]
}

// MapIPs turns an IPs comma separated list of ips or
// ip ranges into a lookup map of the ip strings.
func MapIPs(ips string) (map[string]struct{}, error) {
	mappedIPs := map[string]struct{}{}

	parts := strings.SplitSeq(ips, ",")
	for part := range parts {
		part = strings.TrimSpace(part)
		iprange := strings.Split(part, "-")
		if len(iprange) == 2 {
			start, err := netip.ParseAddr(iprange[0])
			if err != nil {
				return nil, fmt.Errorf("invalid IP range start %s, %s", part, err)
			}
			end, err := netip.ParseAddr(iprange[1])
			if err != nil {
				return nil, fmt.Errorf("invalid IP range end %s, %s", part, err)
			}
			cmp := start.Compare(end)
			if cmp == 0 {
				mappedIPs[start.String()] = struct{}{}
			} else if cmp < 0 {
				for ip := start; ip.Compare(end) <= 0; ip = ip.Next() {
					mappedIPs[ip.String()] = struct{}{}
				}
			} else {
				return nil, fmt.Errorf("invalid IP range %s, end must be greater than start", part)
			}
		} else {
			ip, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("invalid IP %s, %s", part, err)
			}
			mappedIPs[ip.String()] = struct{}{}
		}
	}
	return mappedIPs, nil
}
