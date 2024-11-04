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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

const (
	OSM_USERNAME       = "OSM_USERNAME"
	OSM_PASSWORD       = "OSM_PASSWORD"
	OSM_URL            = "OSM_URL"
	OSM_REGION         = "OSM_REGION"
	OSM_VIM_ACCOUNT    = "OSM_VIM_ACCOUNT"
	OSM_RESOURCE_GROUP = "OSM_RESOURCE_GROUP"
	OSM_SKIPVERIFY     = "OSM_SKIPVERIFY"
)

var AccessVarProps = map[string]*edgeproto.PropertyInfo{
	OSM_USERNAME: {
		Name:      "OpenSource Mano username to authenticate to OSM API",
		Mandatory: true,
	},
	OSM_PASSWORD: {
		Name:      "OpenSource Mano password to authenticate to OSM API",
		Mandatory: true,
	},
	OSM_URL: {
		Name:      "OpenSource Mano API endpoint URL",
		Mandatory: true,
	},
}

var Props = map[string]*edgeproto.PropertyInfo{
	OSM_REGION: {
		Name:      "Region name used when creating clusters",
		Mandatory: true,
	},
	OSM_VIM_ACCOUNT: {
		Name:      "VIM account name used when creating clusters",
		Mandatory: true,
	},
	OSM_RESOURCE_GROUP: {
		Name:      "Resource group of the VIM used when creating clusters",
		Mandatory: true,
	},
	OSM_SKIPVERIFY: {
		Name: "Skip TLS verification on OSM URL (do not use in production), set to any value to enable",
	},
}

func (s *Platform) getAPIURL() string {
	return s.accessVars[OSM_URL]
}

func (s *Platform) getRegion() string {
	val, _ := s.properties.GetValue(OSM_REGION)
	return val
}

func (s *Platform) getVIMAccount() string {
	val, _ := s.properties.GetValue(OSM_VIM_ACCOUNT)
	return val
}

func (s *Platform) getResourceGroup() string {
	val, _ := s.properties.GetValue(OSM_RESOURCE_GROUP)
	return val
}

func (s *Platform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	accessVars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	s.accessVars = accessVars
	return nil
}