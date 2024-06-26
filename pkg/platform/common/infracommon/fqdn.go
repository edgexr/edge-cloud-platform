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

package infracommon

import (
	"context"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

func isDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	ok := false // Ok once we've seen a letter.
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return ok
}

func uri2fqdn(uri string) string {
	fqdn := strings.Replace(uri, "http://", "", 1)
	fqdn = strings.Replace(fqdn, "https://", "", 1)
	//XXX assumes no trailing elements
	return fqdn
}

// ActivateFQDN updates and ensures Fqdn is registered properly
func (c *CommonPlatform) ActivateFQDN(ctx context.Context, fqdn, addr string, ipversion IPVersion) error {
	mappedAddr := c.GetMappedExternalIP(addr)
	recordType := "A"
	if ipversion == IPV6 {
		recordType = "AAAA"
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ActivateFQDN", "fqdn", fqdn, "addr", mappedAddr, "type", recordType)
	return c.PlatformConfig.AccessApi.CreateOrUpdateDNSRecord(ctx, fqdn, recordType, mappedAddr, 1, false)
}
