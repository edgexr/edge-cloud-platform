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

func NBIZone(in *edgeproto.Zone, region string) *nbi.EdgeCloudZone {
	zone := nbi.EdgeCloudZone{}
	zone.EdgeCloudProvider = in.Key.Organization
	zone.EdgeCloudRegion = &region
	zone.EdgeCloudZoneId = in.ObjId
	zone.EdgeCloudZoneName = in.Key.Name
	return &zone
}

func NBIZoneSort(a, b nbi.EdgeCloudZone) int {
	akey := a.EdgeCloudProvider + a.EdgeCloudZoneName
	bkey := b.EdgeCloudProvider + b.EdgeCloudZoneName
	return strings.Compare(akey, bkey)
}
