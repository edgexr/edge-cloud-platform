package testutil

import "github.com/mobiledgex/edge-cloud-infra/mc/ormclient"

// TestClient implements the edge-cloud testutil.Client interface
// so that infra can use the same generated testutil funcs as edge-cloud.
type TestClient struct {
	Uri             string
	Token           string
	Region          string
	McClient        ormclient.Api
	IgnoreForbidden bool
}
