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

package gcp

import (
	"fmt"

	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

const gcpAuthKeyPath string = "/secret/data/cloudlet/gcp/auth_key.json"
const gcpAuthKeyName = "auth_key.json"

var gcpProps = map[string]*edgeproto.PropertyInfo{
	"MEX_GCP_PROJECT": {
		Name:        "GCP Project Name",
		Description: "Name of the GCP project",
		Value:       "still-entity-201400",
	},
	"MEX_GCP_ZONE": {
		Name:        "GCP Zone Name",
		Description: "Name of the GCP zone, e.g. us-central1-a",
		Mandatory:   true,
	},
}

func (g *GCPPlatform) GetGcpRegionFromZone(zone string) (string, error) {
	// region is the zone without part after the last hyphen
	zs := strings.Split(zone, "-")
	if len(zs) < 3 {
		return "", fmt.Errorf("Improperly formatted GCP zone")
	}
	zs = zs[:len(zs)-1]
	return strings.Join(zs, "-"), nil
}

func (g *GCPPlatform) GetGcpZone() string {
	val, _ := g.properties.GetValue("MEX_GCP_ZONE")
	return val
}

func (g *GCPPlatform) GetGcpProject() string {
	val, _ := g.properties.GetValue("MEX_GCP_PROJECT")
	return val
}
