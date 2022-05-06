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

package edgebox

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/dind"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/redundancy"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

// edgebox wraps the generic dind implementation with
// mex-specific behavior, such as setting up DNS and
// registry.mobiledgex.net access secrets.

type EdgeboxPlatform struct {
	generic       dind.Platform
	NetworkScheme string
	commonPf      infracommon.CommonPlatform
	infracommon.CommonEmbedded
}

var edgeboxProps = map[string]*edgeproto.PropertyInfo{
	"MEX_EDGEBOX_NETWORK_SCHEME": &edgeproto.PropertyInfo{
		Name:        "EdgeBox Network Scheme",
		Description: vmlayer.GetSupportedSchemesStr(),
		Value:       cloudcommon.NetworkSchemePrivateIP,
	},
	"MEX_EDGEBOX_DOCKER_USER": &edgeproto.PropertyInfo{
		Name:        "EdgeBox Docker Username",
		Description: "Username to login to docker registry server",
	},
	"MEX_EDGEBOX_DOCKER_PASS": &edgeproto.PropertyInfo{
		Name:        "EdgeBox Docker Password",
		Description: "Password to login to docker registry server",
		Secret:      true,
	},
}

func (e *EdgeboxPlatform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	err := e.generic.InitCommon(ctx, platformConfig, caches, haMgr, updateCallback)
	// Set the test Mode based on what is in PlatformConfig
	infracommon.SetTestMode(platformConfig.TestMode)
	infracommon.SetEdgeboxMode(true)

	if err := e.commonPf.InitInfraCommon(ctx, platformConfig, edgeboxProps); err != nil {
		return err
	}

	e.NetworkScheme = e.GetEdgeboxNetworkScheme()
	if e.NetworkScheme != cloudcommon.NetworkSchemePrivateIP &&
		e.NetworkScheme != cloudcommon.NetworkSchemePublicIP {
		return fmt.Errorf("Unsupported network scheme for DIND: %s", e.NetworkScheme)
	}
	// ensure service ip exists
	_, err = e.GetDINDServiceIP(ctx)
	if err != nil {
		return fmt.Errorf("init cannot get service ip, %s", err.Error())
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "done init edgebox")
	return nil
}

func (e *EdgeboxPlatform) InitHAConditional(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (e *EdgeboxPlatform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "edgebox-1.0"
}

func (e *EdgeboxPlatform) GetEdgeboxNetworkScheme() string {
	val, _ := e.commonPf.Properties.GetValue("MEX_EDGEBOX_NETWORK_SCHEME")
	return val
}

func (e *EdgeboxPlatform) GetEdgeboxDockerCreds() (string, string) {
	user_val, _ := e.commonPf.Properties.GetValue("MEX_EDGEBOX_DOCKER_USER")
	pass_val, _ := e.commonPf.Properties.GetValue("MEX_EDGEBOX_DOCKER_PASS")
	return user_val, pass_val
}

func (o *EdgeboxPlatform) GetFeatures() *platform.Features {
	return &platform.Features{
		SupportsMultiTenantCluster: true,
		CloudletServicesLocal:      true,
	}
}

func (e *EdgeboxPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return e.generic.GatherCloudletInfo(ctx, info)
}

func (s *EdgeboxPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.generic.GetClusterPlatformClient(ctx, clusterInst, clientType)
}

func (s *EdgeboxPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.generic.GetNodePlatformClient(ctx, node)
}

func (s *EdgeboxPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return s.generic.ListCloudletMgmtNodes(ctx, clusterInsts, vmAppInsts)
}

func (s *EdgeboxPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	return &edgeproto.CloudletProps{Properties: edgeboxProps}, nil
}

func (s *EdgeboxPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	return nil, nil
}

func (s *EdgeboxPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return s.generic.GetRootLBClients(ctx)
}

func (s *EdgeboxPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged")
	return nil
}

func (s *EdgeboxPlatform) NameSanitize(name string) string {
	return s.generic.NameSanitize(name)
}
