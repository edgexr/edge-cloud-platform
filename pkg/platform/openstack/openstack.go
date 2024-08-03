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

package openstack

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"unicode"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/vmlayer"
	ssh "github.com/edgexr/golang-ssh"
)

type OpenstackPlatform struct {
	openRCVars   map[string]string
	VMProperties *vmlayer.VMProperties
	caches       *platform.Caches
	apiStats     APIStats
	client       *gophercloud.ProviderClient
}

func NewPlatform() platform.Platform {
	return &vmlayer.VMPlatform{
		VMProvider: &OpenstackPlatform{},
	}
}

type APIStats struct {
	Successful    uint64
	DiscoveryErrs uint64
	OtherErrs     uint64
}

func (o *OpenstackPlatform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	o.VMProperties = vmProperties
}

func (o *OpenstackPlatform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                          platform.PlatformTypeOpenstack,
		SupportsMultiTenantCluster:            true,
		SupportsSharedVolume:                  true,
		SupportsTrustPolicy:                   true,
		SupportsAdditionalNetworks:            true,
		SupportsPlatformHighAvailabilityOnK8S: true,
		SupportsIpv6:                          true,
		AccessVars:                            AccessVarProps,
		Properties:                            OpenstackProps,
		ResourceQuotaProperties:               QuotaProps,
	}
}

func (o *OpenstackPlatform) InitProvider(ctx context.Context, caches *platform.Caches, stage vmlayer.ProviderInitStage, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider", "stage", stage)
	o.InitResourceReservations(ctx)
	if stage == vmlayer.ProviderInitPlatformStartCrmCommon {
		o.initDebug(o.VMProperties.CommonPf.PlatformConfig.NodeMgr)
	} else if stage == vmlayer.ProviderInitPlatformStartCrmConditional {
		return o.PrepNetwork(ctx, updateCallback)
	}
	return nil
}

func (a *OpenstackPlatform) InitOperationContext(ctx context.Context, operationStage vmlayer.OperationInitStage) (context.Context, vmlayer.OperationInitResult, error) {
	return ctx, vmlayer.OperationNewlyInitialized, nil
}

func (o *OpenstackPlatform) InitData(ctx context.Context, caches *platform.Caches) {
	o.caches = caches
}

var cmdToService = map[string]string{
	"image":        "image",
	"availability": "compute",
	"console":      "compute",
	"flavor":       "compute",
	"limits":       "compute",
	"server":       "compute",
	"floating":     "network",
	"network":      "network",
	"port":         "network",
	"router":       "network",
	"security":     "network",
	"subnet":       "network",
	"stack":        "orchestration",
	"project":      "identity",
}

const (
	ServiceCompute       = "compute"
	ServiceNetwork       = "network"
	ServiceImage         = "image"
	ServiceOrchestration = "orchestration"
	ServiceIdentity      = "identity"
)

func (o *OpenstackPlatform) getServiceClient(service string) (*gophercloud.ServiceClient, error) {
	client, err := o.getClient()
	if err != nil {
		return nil, err
	}
	ep := gophercloud.EndpointOpts{
		Region: o.openRCVars[OS_REGION_NAME],
	}
	switch service {
	case ServiceCompute:
		return openstack.NewComputeV2(client, ep)
	case ServiceNetwork:
		return openstack.NewNetworkV2(client, ep)
	case ServiceImage:
		return openstack.NewImageServiceV2(client, ep)
	case ServiceOrchestration:
		return openstack.NewOrchestrationV1(client, ep)
	case ServiceIdentity:
		return openstack.NewIdentityV2(client, ep)
	default:
		return nil, fmt.Errorf("get client unsupported service %s", service)
	}
}

func (o *OpenstackPlatform) getClient() (*gophercloud.ProviderClient, error) {
	if o.client != nil {
		return o.client, nil
	}
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: o.openRCVars[OS_AUTH_URL],
		Username:         o.openRCVars[OS_USERNAME],
		Password:         o.openRCVars[OS_PASSWORD],
		DomainName:       o.openRCVars[OS_USER_DOMAIN_NAME],
	}
	client, err := openstack.NewClient(opts.IdentityEndpoint)
	if err != nil {
		return nil, err
	}
	caPEM, ok := o.openRCVars[OS_CACERT_DATA]
	if !ok {
		if caFile := o.openRCVars[OS_CACERT]; caFile != "" {
			data, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read file %s, %s", caFile, err)
			}
			caPEM = string(data)
		}
	}
	if caPEM != "" {
		caPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		ok := caPool.AppendCertsFromPEM([]byte(caPEM))
		if !ok {
			return nil, fmt.Errorf("failed to add CA cert to CA pool")
		}
		client.HTTPClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		}
	}
	err = openstack.Authenticate(client, opts)
	if err != nil {
		return nil, err
	}
	o.client = client
	return client, nil
}

func (o *OpenstackPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return o.OSGetLimits(ctx, info)
}

// alphanumeric plus -_. first char must be alpha, <= 255 chars.
func (o *OpenstackPlatform) NameSanitize(name string) string {
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "",
		"!", "")
	str := r.Replace(name)
	if str == "" {
		return str
	}
	if !unicode.IsLetter(rune(str[0])) {
		// first character must be alpha
		str = "a" + str
	}
	if len(str) > 255 {
		str = str[:254]
	}
	return str
}

// Openstack IdSanitize is the same as NameSanitize
func (o *OpenstackPlatform) IdSanitize(name string) string {
	return o.NameSanitize(name)
}

func (o *OpenstackPlatform) DeleteResources(ctx context.Context, resourceGroupName string) error {
	return o.HeatDeleteStack(ctx, resourceGroupName)
}

func (o *OpenstackPlatform) GetResourceID(ctx context.Context, resourceType vmlayer.ResourceType, resourceName string) (string, error) {
	switch resourceType {
	case vmlayer.ResourceTypeSecurityGroup:
		// for testing mode, don't try to run APIs just fake a value
		if o.VMProperties.CommonPf.PlatformConfig.TestMode {
			return resourceName + "-testingID", nil
		}
		return o.GetSecurityGroupIDForName(ctx, resourceName)
		// TODO other types as needed
	}
	return "", fmt.Errorf("GetResourceID not implemented for resource type: %s ", resourceType)
}

func (o *OpenstackPlatform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, TrustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	// nothing to do
	return nil
}
