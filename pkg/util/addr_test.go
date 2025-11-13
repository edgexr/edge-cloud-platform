// Copyright 2025 EdgeXR, Inc
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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPRanges(t *testing.T) {
	tests := []struct {
		desc   string
		ips    string
		out    []string
		expErr string
	}{{
		"single ip",
		"192.168.1.100",
		[]string{"192.168.1.100"}, "",
	}, {
		"ip list",
		"192.168.1.100,192.168.1.101",
		[]string{"192.168.1.100", "192.168.1.101"}, "",
	}, {
		"ip range",
		"192.168.1.100-192.168.1.105",
		[]string{
			"192.168.1.100",
			"192.168.1.101",
			"192.168.1.102",
			"192.168.1.103",
			"192.168.1.104",
			"192.168.1.105",
		}, "",
	}, {
		"ip list with range",
		"192.168.1.100-192.168.1.105,192.168.1.108",
		[]string{
			"192.168.1.100",
			"192.168.1.101",
			"192.168.1.102",
			"192.168.1.103",
			"192.168.1.104",
			"192.168.1.105",
			"192.168.1.108",
		}, "",
	}, {
		"ip list with range with overlap",
		"192.168.1.100-192.168.1.105,192.168.1.103",
		[]string{
			"192.168.1.100",
			"192.168.1.101",
			"192.168.1.102",
			"192.168.1.103",
			"192.168.1.104",
			"192.168.1.105",
		}, "",
	}, {
		"duplicate ips",
		"192.168.1.101,192.168.1.101",
		[]string{"192.168.1.101"}, "",
	}, {
		"mutliple ip ranges, overlapping",
		"192.168.1.100-192.168.1.105,192.168.1.103-192.168.1.108",
		[]string{
			"192.168.1.100",
			"192.168.1.101",
			"192.168.1.102",
			"192.168.1.103",
			"192.168.1.104",
			"192.168.1.105",
			"192.168.1.106",
			"192.168.1.107",
			"192.168.1.108",
		}, "",
	}, {
		"invalid ip",
		"192.168.1.100,192.168.1.1O1",
		nil, "invalid IP 192.168.1.1O1",
	}, {
		"invalid ip range start",
		"192.168.1.10O-192.168.1.105",
		nil, "invalid IP range start",
	}, {
		"invalid ip range end",
		"192.168.1.100-192.168.1.1O5",
		nil, "invalid IP range end",
	}, {
		"invalid ip range, start > end",
		"192.168.1.101-192.168.1.100",
		nil, "end must be greater than start",
	}}
	for _, test := range tests {
		err := ValidateIPRanges(test.ips)
		if test.expErr != "" {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.expErr, test.desc)
		} else {
			require.NoError(t, err, test.desc)
			ips := []string{}
			for ip := range IPRangesIter(test.ips) {
				ips = append(ips, ip)
			}
			require.Equal(t, test.out, ips, test.desc)
		}
	}
}
