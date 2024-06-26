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

package k8sbm

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

var k8sbmProps = map[string]*edgeproto.PropertyInfo{
	"K8S_CONTROL_ACCESS_IP": {
		Name:        "K8S Control Access IP",
		Description: "IP used to access the control plane externally",
		Mandatory:   true,
	},
	"K8S_EXTERNAL_IP_RANGES": {
		Name:        "External IP Ranges(s) for K8S Load Balancers",
		Description: "Range of External IP addresses for K8S LBs, Format: StartCIDR-EndCIDR,StartCIDR2-EndCIDR2,...",
		Mandatory:   true,
	},
	"K8S_EXTERNAL_ETH_INTERFACE": {
		Name:        "External Ethernet Interface",
		Description: "Ethernet interface used for K8S LB, e.g. eno2",
		Mandatory:   true,
	},
}

var quotaProps = cloudcommon.GetCommonResourceQuotaProps(
	cloudcommon.ResourceExternalIPs,
)

func (k *K8sBareMetalPlatform) GetControlAccessIp() string {
	value, _ := k.commonPf.Properties.GetValue("K8S_CONTROL_ACCESS_IP")
	return value
}

func (k *K8sBareMetalPlatform) GetExternalIpRanges() string {
	value, _ := k.commonPf.Properties.GetValue("K8S_EXTERNAL_IP_RANGES")
	return value
}

func (k *K8sBareMetalPlatform) GetExternalEthernetInterface() string {
	value, _ := k.commonPf.Properties.GetValue("K8S_EXTERNAL_ETH_INTERFACE")
	return value
}
