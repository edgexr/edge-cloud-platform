package shepherd_unittest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type Platform struct {
	// Contains the response string for a given type of a request
	DockerAppMetrics     string
	DockerClusterMetrics string
	// TODO - add Prometheus/nginx strings here EDGECLOUD-1252
}

func (s *Platform) GetType() string {
	return "unit test"
}

func (s *Platform) Init(ctx context.Context, key *edgeproto.CloudletKey, physicalName, vaultAddr string) error {
	return nil
}

func (s *Platform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	return "localhost", nil
}

func (s *Platform) GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error) {
	return &UTClient{pf: s}, nil
}

// UTClient hijacks a set of commands and returns predetermined output
// For all other commands it just calls pc.LocalClient equivalents
type UTClient struct {
	pc.LocalClient
	pf *Platform
}

func (s *UTClient) Output(command string) (string, error) {
	out, err := s.getUTData(command)
	if err != nil {
		return s.Output(command)
	}
	return out, nil
}

func (s *UTClient) getUTData(command string) (string, error) {
	str := ""
	// docker stats unit test
	if strings.Contains(command, "docker stats ") {
		// take the json with line breaks and compact it, as that's what the command expects
		str = s.pf.DockerAppMetrics
	} else if strings.Contains(command, "resource-tracker") {
		str = s.pf.DockerClusterMetrics
	}
	if str != "" {
		buf := new(bytes.Buffer)
		if err := json.Compact(buf, []byte(str)); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	return "", fmt.Errorf("No UT Data found")
}
