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
	"iter"
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

// ValidateIPRanges checks that the passed in string is
// comma-separated list of ips or ip ranges.
// See the unit test for example strings.
func ValidateIPRanges(ips string) error {
	parts := strings.SplitSeq(ips, ",")
	for part := range parts {
		part = strings.TrimSpace(part)
		iprange := strings.Split(part, "-")
		if len(iprange) == 2 {
			start, err := netip.ParseAddr(iprange[0])
			if err != nil {
				return fmt.Errorf("invalid IP range start %s, %s", part, err)
			}
			end, err := netip.ParseAddr(iprange[1])
			if err != nil {
				return fmt.Errorf("invalid IP range end %s, %s", part, err)
			}
			cmp := start.Compare(end)
			if cmp > 0 {
				return fmt.Errorf("invalid IP range %s, end must be greater than start", part)
			}
		} else {
			_, err := netip.ParseAddr(part)
			if err != nil {
				return fmt.Errorf("invalid IP %s, %s", part, err)
			}
		}
	}
	return nil
}

// IPRangesIter iterates in order over the specified IP ranges.
// It avoids duplicate IPs.
func IPRangesIter(ips string) iter.Seq[string] {
	return func(yield func(string) bool) {
		found := map[string]struct{}{}
		// doYield avoids duplicate IPs
		doYield := func(ip string) bool {
			if _, ok := found[ip]; ok {
				return true
			}
			found[ip] = struct{}{}
			return yield(ip)
		}

		for arange := range strings.SplitSeq(ips, ",") {
			arange = strings.TrimSpace(arange)
			iprange := strings.Split(arange, "-")
			if len(iprange) == 2 {
				start, err := netip.ParseAddr(iprange[0])
				if err != nil {
					continue
				}
				end, err := netip.ParseAddr(iprange[1])
				if err != nil {
					continue
				}
				cmp := start.Compare(end)
				if cmp == 0 {
					if !doYield(start.String()) {
						return
					}
				} else if cmp < 0 {
					for ip := start; ip.Compare(end) <= 0; ip = ip.Next() {
						if !doYield(ip.String()) {
							return
						}
					}
				}
			} else {
				if !doYield(arange) {
					return
				}
			}
		}
	}
}
