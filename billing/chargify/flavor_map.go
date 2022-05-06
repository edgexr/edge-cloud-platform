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

package chargify

import (
	"strings"
	"time"

	"github.com/edgexr/edge-cloud/edgeproto"
)

var dmeApiCode = "dmeapi"

// gets the corresponding compoenent code for the flavor
func getComponentCode(flavor, region string, cloudlet *edgeproto.CloudletKey, start, end time.Time) string {
	// CURRENT FLAVOR HANDLE STRUCTURE: region-cloudletOrg-cloudletName-flavor
	regionName := handleSanitize(region)
	org := handleSanitize(cloudlet.Organization)
	name := handleSanitize(cloudlet.Name)
	flavorName := handleSanitize(flavor)
	return "handle:" + regionName + "-" + org + "-" + name + "-" + flavorName
}

func handleSanitize(name string) string {
	// Handle must start with a letter or number and may only contain lowercase letters, numbers, or the characters ':', '-', or '_'
	// replace .&,!
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "",
		".", "",
		"!", "")
	return r.Replace(name)
}
