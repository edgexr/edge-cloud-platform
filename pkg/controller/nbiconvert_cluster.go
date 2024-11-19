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

package controller

import (
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
)

func (s *NBIAPI) NBICluster(in *edgeproto.ClusterInst) *nbi.ClusterInfo {
	cluster := nbi.ClusterInfo{}
	cluster.ClusterRef = in.ObjId
	cluster.Name = in.Key.Name
	cluster.Provider = in.Key.Organization
	zone := edgeproto.Zone{}
	if s.allApis.zoneApi.cache.Get(&in.ZoneKey, &zone) {
		cluster.EdgeCloudZoneId = zone.ObjId
	}
	return &cluster
}

func NBIClusterSort(a, b nbi.ClusterInfo) int {
	akey := a.Provider + a.Name
	bkey := b.Provider + b.Name
	return strings.Compare(akey, bkey)
}