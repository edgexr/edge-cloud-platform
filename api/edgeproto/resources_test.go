// Copyright 2024 EdgeXR, Inc
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

package edgeproto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodePoolResourcesValidate(t *testing.T) {
	tests := []struct {
		desc      string
		in        *NodePoolResources
		err       string
		checkFunc func(out *NodePoolResources, desc string)
	}{{
		desc: "total vcpus gt 0",
		in: &NodePoolResources{
			TotalMemory: 1024,
		},
		err: "total required vcpus must be greater than 0",
	}, {
		desc: "total mem gt 0",
		in: &NodePoolResources{
			TotalVcpus: *NewUdec64(1, 0),
		},
		err: "total required memory must be greater than 0",
	}, {
		desc: "min values default 1",
		in: &NodePoolResources{
			TotalVcpus:  *NewUdec64(1, 0),
			TotalMemory: 1024,
		},
		checkFunc: func(out *NodePoolResources, desc string) {
			require.Equal(t, int32(1), out.Topology.MinNumberOfNodes, desc)
		},
	}, {
		desc: "no changes, fully specified",
		in: &NodePoolResources{
			TotalVcpus:  *NewUdec64(16, 0),
			TotalMemory: 14336,
			Topology: NodePoolTopology{
				MinNumberOfNodes: 3,
				MinNodeVcpus:     2,
				MinNodeMemory:    4096,
			},
		},
		checkFunc: func(out *NodePoolResources, desc string) {
			require.Equal(t, int32(3), out.Topology.MinNumberOfNodes, desc)
			require.Equal(t, uint64(2), out.Topology.MinNodeVcpus, desc)
			require.Equal(t, uint64(4096), out.Topology.MinNodeMemory, desc)
		},
	}}
	for _, test := range tests {
		err := test.in.Validate()
		if test.err != "" {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.err, test.desc)
		} else {
			require.Nil(t, err, test.desc)
		}
		if test.checkFunc != nil {
			test.checkFunc(test.in, test.desc)
		}
	}
}
