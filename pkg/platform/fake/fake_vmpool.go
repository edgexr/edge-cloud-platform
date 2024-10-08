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

package fake

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

type PlatformVMPool struct {
	Platform
}

func NewPlatformVMPool() platform.Platform {
	return &PlatformVMPool{}
}

func (s *PlatformVMPool) GetFeatures() *edgeproto.PlatformFeatures {
	features := s.Platform.GetFeatures()
	features.PlatformType = platform.PlatformTypeFakeVMPool
	features.IsVmPool = true
	features.RequiresCrmOnEdge = true
	return features
}
