package fake

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

type PlatformFakeEdgebox struct {
	Platform
}

func NewPlatformFakeEdgebox() platform.Platform {
	return &PlatformFakeEdgebox{}
}

func (s *PlatformFakeEdgebox) GetFeatures() *edgeproto.PlatformFeatures {
	features := s.Platform.GetFeatures()
	features.PlatformType = platform.PlatformTypeFakeEdgebox
	features.IsEdgebox = true
	return features
}
