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

package osmk8s

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/test-go/testify/require"
)

func TestGatherCloudletInfo(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	s := Platform{}
	s.properties = &infracommon.InfraProperties{
		Properties: make(map[string]*edgeproto.PropertyInfo),
	}
	s.properties.SetProperties(Props)
	s.properties.SetValue(OSM_FLAVORS, `[{"name":"Standard_D2s_v3","vcpus":2,"ram":8192,"disk":16}]`)

	flavors := []*edgeproto.FlavorInfo{{
		Name:  "Standard_D2s_v3",
		Vcpus: 2,
		Ram:   8192,
		Disk:  16,
	}}
	info := &edgeproto.CloudletInfo{}
	err := s.GatherCloudletInfo(ctx, info)
	require.Nil(t, err)
	require.Equal(t, flavors, info.Flavors)
}
