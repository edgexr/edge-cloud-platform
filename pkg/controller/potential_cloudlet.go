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

package controller

import (
	"context"
	"sort"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// potentialInstCloudlet is a potential cloudlet to consider when
// determining where to deploy an instance in a zone.
type potentialInstCloudlet struct {
	cloudlet        edgeproto.Cloudlet
	cloudletInfo    edgeproto.CloudletInfo
	features        *edgeproto.PlatformFeatures
	flavorLookup    edgeproto.FlavorLookup
	resCalc         *CloudletResCalc
	cloudletUsedRes *CloudletResources
	resourceScore   uint64
}

// SkipReason are reasons that a cloudlet was not considered
// for deploying an instance. We use this to convey information
// to developers instead of the actual errors because the errors
// may contain cloudlet-specific information that should be hidden
// from developers.
type SkipReason string

const (
	NoSkipReason                SkipReason = ""
	SiteUnavailable                        = "site is unavailable"
	SiteFeaturesMissing                    = "site features are missing"
	SiteTrustPolicyMissing                 = "site trust policy is missing"
	NoSupportDedicatedIP                   = "platform does not support dedicated IP"
	NoSupportIPV6                          = "platform does not support IPV6"
	KubernetesOnly                         = "platform only supports kubernetes"
	ServerlessOnly                         = "platform only supports serverless apps"
	RequiresTrustedApp                     = "site requires trusted app"
	IncompatibleTrustPolicy                = "app not compatible with site trust policy"
	UnsupportedImageType                   = "site does not support app image type"
	NoSupportClusterInst                   = "site only supports AppInst creates"
	NoSupportSharedVolumes                 = "site does not support shared volumes"
	RequiresNodePools                      = "site requires at least one node pool"
	NoSupportMultiTenantCluster            = "site does not support multi-tenant clusters"
	NoSupportNetworks                      = "site does not support additional networks"
	NoSupportSharedIPAccess                = "site does not support shared IP access"
	NoSupportDedicatedIPAccess             = "site does not support dedicated IP access"
	MTClusterOrgInvalid                    = "invalid organization for multi-tenant cluster"
	NoSupportMultipleNodePools             = "site does not support multiple node pools"
)

type SkipReasons map[SkipReason]struct{}

func (s SkipReasons) add(reason SkipReason) {
	if reason != NoSkipReason {
		s[reason] = struct{}{}
	}
}

func (s SkipReasons) String() string {
	if len(s) == 0 {
		return ""
	}
	reasons := []string{}
	for reason := range s {
		reasons = append(reasons, string(reason))
	}
	sort.Strings(reasons)
	return strings.Join(reasons, ", ")
}

func (s *potentialInstCloudlet) initResCalc(ctx context.Context, all *AllApis, stm concurrency.STM) error {
	resCalc := NewCloudletResCalc(all, edgeproto.NewOptionalSTM(stm), &s.cloudlet.Key)
	resCalc.deps.cloudlet = &s.cloudlet
	resCalc.deps.cloudletInfo = &s.cloudletInfo
	resCalc.deps.features = s.features
	if err := resCalc.InitDeps(ctx); err != nil {
		return err
	}
	// cache used values for sorting
	usedVals, err := resCalc.getUsedResVals(ctx)
	if err != nil {
		return err
	}
	s.resCalc = resCalc
	s.resourceScore = resCalc.calcResourceScoreFromUsed(usedVals)
	log.SpanLog(ctx, log.DebugLevelApi, "potentialInstCloudlet calcResourceScore", "cloudlet", resCalc.cloudletKey, "score", s.resourceScore, "used", usedVals.String())
	return nil
}

// PotentialInstCloudletsByResource sorts potential cloudlets
// based on available resources. Cloudlets with the most available resources
// come first in the list. To avoid overloading the STM with too many
// read objects, we do not use the STM. The caller will need to
// actually reserve resources as part of an STM once a cloudlet is chosen.
// This sorting just gives priority based on available resources.
// Since this not a guarantee and we are not using an STM, it is easier
// to just look at the infra-reported in-use values rather than calculating
// the theoretical values.
type PotentialInstCloudletsByResource []*potentialInstCloudlet

func (a PotentialInstCloudletsByResource) Len() int {
	return len(a)
}

func (a PotentialInstCloudletsByResource) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a PotentialInstCloudletsByResource) Less(i, j int) bool {
	// for now just take into account RAM and VCPU.
	iscore := a[i].resourceScore
	jscore := a[j].resourceScore
	if iscore == jscore {
		return a[i].cloudlet.Key.GetKeyString() < a[j].cloudlet.Key.GetKeyString()
	}
	return iscore > jscore
}
