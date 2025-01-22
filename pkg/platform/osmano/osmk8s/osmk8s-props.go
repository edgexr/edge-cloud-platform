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
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

const (
	OSM_FLAVORS = "OSM_FLAVORS"
)

var Props = map[string]*edgeproto.PropertyInfo{
	OSM_FLAVORS: {
		Name:        "List of flavors in JSON format since OSM does not provide a way to query for VIM flavors",
		Description: `JSON formatted list of edgeproto.FlavorInfo, i.e. [{"name":"Standard_D2s_v3","vcpus":2,"ram":8192,"disk":16}]`,
	},
}
