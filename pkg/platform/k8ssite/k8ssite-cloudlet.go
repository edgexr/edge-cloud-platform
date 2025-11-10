// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8ssite

import (
	"context"
	"fmt"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
)

func (s *K8sSite) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "cloudletState", cloudletState)
	return nil
}

func (s *K8sSite) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest not supported", "cloudletName", cloudlet.Key.Name)
	return nil, fmt.Errorf("GetCloudletManifest not supported")
}

func (s *K8sSite) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyVMs nothing to do")
	return nil
}

func (s *K8sSite) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletInfraResources")
	// TODO
	return &edgeproto.InfraResourcesSnapshot{}, nil
}

func (s *K8sSite) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)

	platConfig := infracommon.GetPlatformConfig(cloudlet, pfConfig, pfInitConfig)
	err := s.InitCommon(ctx, platConfig, caches, nil, updateCallback)
	if err != nil {
		return false, err
	}
	kconfNames, err := s.ensureKubeconfig()
	if err != nil {
		return false, err
	}
	client := s.getClient()

	wildcardName := certscache.GetWildcardName(cloudlet.RootLbFqdn)
	refreshOpts := k8smgmt.RefreshCertsOpts{
		CommerialCerts: s.CommonPf.PlatformConfig.CommercialCerts,
		InitCluster:    true,
	}
	if s.weManageIngressController(cloudlet) {
		nsLabels, err := s.CommonPf.Properties.GetJSONMapValue(cloudcommon.NamespaceLabels)
		if err != nil {
			return false, err
		}
		err = k8smgmt.SetupIngressNginx(ctx, client, kconfNames, &cloudlet.Key, pfInitConfig.ProxyCertsCache, wildcardName, refreshOpts, nsLabels, updateCallback)
		if err != nil {
			return false, err
		}
	} else {
		// TODO: for now we're only maintaining the cert in the
		// default namespace, but we'd need to populate it for
		// all namespaces.
		ns := k8smgmt.DefaultNamespace
		if cloudlet.SingleKubernetesNamespace != "" {
			ns = cloudlet.SingleKubernetesNamespace
		}
		updateCallback(edgeproto.UpdateTask, "Generating ingress certificate")
		// set up certificate in default namespace
		err = k8smgmt.RefreshCert(ctx, client, kconfNames, &cloudlet.Key, pfInitConfig.ProxyCertsCache, ns, wildcardName, refreshOpts)
		if err != nil {
			return false, err
		}
	}
	return false, nil
}

func (s *K8sSite) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sSite) ChangeCloudletDNS(ctx context.Context, cloudlet *edgeproto.Cloudlet, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sSite) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "update ManagedK8sPlatform TrustPolicy", "policy", TrustPolicy)
	return fmt.Errorf("UpdateTrustPolicy not supported")
}
func (s *K8sSite) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterKey *edgeproto.ClusterKey) error {
	return fmt.Errorf("UpdateTrustPolicyException TODO")
}

func (s *K8sSite) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterKey *edgeproto.ClusterKey) error {
	return fmt.Errorf("DeleteTrustPolicyException TODO")
}

func (s *K8sSite) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet", "cloudlet", cloudlet)
	return nil
}

func (s *K8sSite) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sSite) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *K8sSite) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{}, nil
}

func (s *K8sSite) ActiveChanged(ctx context.Context, platformActive bool) error {
	return nil
}

func (s *K8sSite) RefreshCerts(ctx context.Context, certsCache *certscache.ProxyCertsCache) error {
	// there is just one certificate for the cluster
	cloudletKey := s.CommonPf.PlatformConfig.CloudletKey
	cloudlet := &edgeproto.Cloudlet{}
	if !s.caches.CloudletCache.Get(cloudletKey, cloudlet) {
		return cloudletKey.NotFoundError()
	}
	kconfNames, err := s.ensureKubeconfig()
	if err != nil {
		return err
	}
	client := s.getClient()

	var namespace string
	if s.weManageIngressController(cloudlet) {
		namespace = k8smgmt.IngressNginxNamespace
	} else {
		namespace = k8smgmt.DefaultNamespace
		if cloudlet.SingleKubernetesNamespace != "" {
			namespace = cloudlet.SingleKubernetesNamespace
		}
	}

	wildcardName := certscache.GetWildcardName(cloudlet.RootLbFqdn)
	refreshOpts := k8smgmt.RefreshCertsOpts{
		CommerialCerts: s.CommonPf.PlatformConfig.CommercialCerts,
	}
	err = k8smgmt.RefreshCert(ctx, client, kconfNames, cloudletKey, certsCache, namespace, wildcardName, refreshOpts)
	if err != nil {
		return err
	}
	return nil
}

func (s *K8sSite) weManageIngressController(cloudlet *edgeproto.Cloudlet) bool {
	if cloudlet.SingleKubernetesNamespace != "" {
		// we are limited to a restricted namespace, assume operator
		// manages the ingress controller for the cluster.
		return false
	}
	hasIngressController, ok := s.CommonPf.Properties.GetValue(cloudcommon.IngressControllerPresent)
	if ok && hasIngressController != "" {
		// user has specified that the ingress controller is already
		// present and managed by them.
		return false
	}
	return true
}
