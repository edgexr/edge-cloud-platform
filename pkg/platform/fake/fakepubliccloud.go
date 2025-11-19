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

package fake

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

type PlatformPublicCloud struct {
	Platform
}

func NewPlatformPublicCloud() platform.Platform {
	pf := &PlatformPublicCloud{}
	pf.Platform.simPublicCloud = true
	return pf
}

func (s *PlatformPublicCloud) GetFeatures() *edgeproto.PlatformFeatures {
	// features mirror a public cloud platform like AWS/AzureAKS
	features := s.Platform.GetFeatures()
	features.PlatformType = platform.PlatformTypeFakePublicCloud
	features.KubernetesManagedControlPlane = true
	features.IpAllocatedPerService = true
	features.ManagesK8SControlNodes = true
	features.RequiresCrmOffEdge = true
	return features
}
