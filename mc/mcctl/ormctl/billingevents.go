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

package ormctl

import (
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
)

const BillingEventsGroup = "BillingEvents"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "ShowAppEvents",
		Use:          "app",
		Short:        "View App billing events",
		RequiredArgs: strings.Join(append([]string{"region"}, AppEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(BillingEventsCommonArgs, AppEventOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(MetricsCommonAliasArgs, AppEventAliasArgs...), " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionAppInstEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/events/app",
	}, &ApiCommand{
		Name:         "ShowClusterEvents",
		Use:          "cluster",
		Short:        "View ClusterInst billing events",
		RequiredArgs: strings.Join(append([]string{"region"}, ClusterEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(BillingEventsCommonArgs, ClusterEventOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(MetricsCommonAliasArgs, ClusterEventAliasArgs...), " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionClusterInstEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/events/cluster",
	}, &ApiCommand{
		Name:         "ShowCloudletEvents",
		Use:          "cloudlet",
		Short:        "View Cloudlet billing events",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(BillingEventsCommonArgs, CloudletEventOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(MetricsCommonAliasArgs, CloudletEventAliasArgs...), " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionCloudletEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/events/cloudlet",
	}}
	AllApis.AddGroup(BillingEventsGroup, "View billing events ", cmds)
}

var BillingEventsCommonArgs = []string{
	"limit",
	"starttime",
	"endtime",
	"startage",
	"endage",
}

var AppEventRequiredArgs = []string{}

var AppEventOptionalArgs = []string{
	"appname",
	"apporg",
	"appvers",
	"cluster",
	"cloudlet",
	"cloudletorg",
}

var AppEventAliasArgs = []string{
	"apporg=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cloudletorg=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClusterEventRequiredArgs = []string{}

var ClusterEventOptionalArgs = []string{
	"cluster",
	"clusterorg",
	"cloudletorg",
	"cloudlet",
}

var ClusterEventAliasArgs = []string{
	"clusterorg=clusterinst.organization",
	"cluster=clusterinst.clusterkey.name",
	"cloudletorg=clusterinst.cloudletkey.organization",
	"cloudlet=clusterinst.cloudletkey.name",
}

var CloudletEventRequiredArgs = []string{
	"cloudletorg",
}

var CloudletEventOptionalArgs = []string{
	"cloudlet",
}

var CloudletEventAliasArgs = []string{
	"cloudletorg=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

var EventComments = map[string]string{
	"apporg":      "Organization or Company Name that a Developer is part of",
	"appname":     "App name",
	"appvers":     "App version",
	"cluster":     "Cluster name",
	"clusterorg":  "Organization or Company Name that a Cluster is used by",
	"cloudletorg": "Organization name owning of the cloudlet",
	"cloudlet":    "Name of the cloudlet",
	"limit":       "Display the last X events",
	"starttime":   "Time to start displaying stats from in RFC3339 format (ex. 2002-12-31T15:00:00Z)",
	"endtime":     "Time up to which to display stats in RFC3339 format (ex. 2002-12-31T10:00:00-05:00)",
	"startage":    "Relative age from now of search range start (default 48h)",
	"endage":      "Relative age from now of search range end (default 0)",
}
