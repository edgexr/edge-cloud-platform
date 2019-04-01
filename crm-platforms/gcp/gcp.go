package gcp

import (
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type Platform struct {
	// GcpProperties needs to move to edge-cloud-infra
	props edgeproto.GcpProperties
}

func (s *Platform) GetType() string {
	return "gcp"
}

func (s *Platform) Init(key *edgeproto.CloudletKey) error {
	if err := mexos.InitInfraCommon(); err != nil {
		return err
	}
	s.props.Project = os.Getenv("MEX_GCP_PROJECT")
	if s.props.Project == "" {
		//default
		s.props.Project = "still-entity-201400"
	}
	s.props.Zone = os.Getenv("MEX_GCP_ZONE")
	if s.props.Zone == "" {
		return fmt.Errorf("Env variable MEX_GCP_ZONE not set")
	}
	return nil
}

func (s *Platform) GatherCloudletInfo(info *edgeproto.CloudletInfo) error {
	// TODO: pull in new code from mexos/stats.go
	return nil
}

func (s *Platform) GetPlatformClient() pc.PlatformClient {
	return &pc.LocalClient{}
}
