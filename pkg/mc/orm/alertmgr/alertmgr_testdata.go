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

package alertmgr

import (
	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

var TestInitInfo = AlertmgrInitInfo{
	Email:          "alerts@localhost",
	User:           "testuser",
	Token:          "12345",
	Smtp:           "localhost",
	Port:           "25",
	Tls:            "false",
	ResolveTimeout: "2m",
}

var testRegions = []string{"testRegion1", "testRegion2"}
var testUsers = []string{"testuser1", "testuser2"}

var testAlerts = []edgeproto.Alert{
	edgeproto.Alert{
		Labels: map[string]string{
			"alertname":                        cloudcommon.AlertAppInstDown,
			"region":                           testRegions[0],
			edgeproto.AppKeyTagName:            "testapp",
			edgeproto.AppKeyTagOrganization:    "testorg",
			edgeproto.AppKeyTagVersion:         "1.0",
			edgeproto.CloudletKeyTagName:       "testcloudlet",
			cloudcommon.AlertSeverityLabel:     cloudcommon.AlertSeverityError,
			cloudcommon.AlertHealthCheckStatus: dme.HealthCheck_CamelName[int32(dme.HealthCheck_HEALTH_CHECK_ROOTLB_OFFLINE)],
		},
	},
	edgeproto.Alert{ //testAlerts[0], but in a different region
		Labels: map[string]string{
			"alertname":                        cloudcommon.AlertAppInstDown,
			"region":                           testRegions[1],
			edgeproto.AppKeyTagName:            "testapp",
			edgeproto.AppKeyTagOrganization:    "testorg",
			edgeproto.AppKeyTagVersion:         "1.0",
			edgeproto.CloudletKeyTagName:       "testcloudlet",
			cloudcommon.AlertSeverityLabel:     cloudcommon.AlertSeverityError,
			cloudcommon.AlertHealthCheckStatus: dme.HealthCheck_CamelName[int32(dme.HealthCheck_HEALTH_CHECK_ROOTLB_OFFLINE)],
		},
	},
	edgeproto.Alert{ // AlertAutoUndeploy alert
		Labels: map[string]string{
			"alertname":                     cloudcommon.AlertAutoUndeploy,
			"region":                        testRegions[1],
			edgeproto.AppKeyTagName:         "testapp",
			edgeproto.AppKeyTagOrganization: "testorg",
			edgeproto.AppKeyTagVersion:      "1.0",
			edgeproto.CloudletKeyTagName:    "testcloudlet",
		},
	},
}

var testAlertReceivers = []ormapi.AlertReceiver{
	ormapi.AlertReceiver{
		Name:     "invalidReceiver",
		Type:     "invalidType",
		Severity: cloudcommon.AlertSeverityError,
		User:     testUsers[0],
	},
	ormapi.AlertReceiver{
		Name:     "testorgemailreceiver",
		Type:     AlertReceiverTypeEmail,
		Severity: cloudcommon.AlertSeverityError,
		User:     testUsers[0],
		Email:    "testuser1@testorg.net",
		AppInstKey: edgeproto.AppInstKey{
			Name:         "testAppInst",
			Organization: "testAppOrg",
			CloudletKey: edgeproto.CloudletKey{
				Name:         "testCloudlet",
				Organization: "testCloudletOrg",
			},
		},
	},
	ormapi.AlertReceiver{
		Name:         "testorgslackreceiverInvalidSlackData",
		Type:         AlertReceiverTypeSlack,
		Severity:     cloudcommon.AlertSeverityError,
		User:         testUsers[0],
		SlackChannel: "#alerts",
		SlackWebhook: "invalidURL",
		AppInstKey: edgeproto.AppInstKey{
			Name:         "testAppInst",
			Organization: "testAppOrg",
			CloudletKey: edgeproto.CloudletKey{
				Name:         "testCloudlet",
				Organization: "testCloudletOrg",
			},
		},
	},
	ormapi.AlertReceiver{
		Name:         "testorgslackreceiver",
		Type:         AlertReceiverTypeSlack,
		Severity:     cloudcommon.AlertSeverityError,
		User:         testUsers[1],
		SlackChannel: "#alerts",
		SlackWebhook: "https://hooks.slack.com/foo",
		AppInstKey: edgeproto.AppInstKey{
			Name:         "testAppInst",
			Organization: "testAppOrg",
			CloudletKey: edgeproto.CloudletKey{
				Name:         "testCloudlet",
				Organization: "testCloudletOrg",
			},
		},
	},
	ormapi.AlertReceiver{
		Name:     "testclusteremailreceiver",
		Type:     AlertReceiverTypeEmail,
		Severity: cloudcommon.AlertSeverityError,
		User:     testUsers[0],
		Email:    "testuser1@testorg.net",
		ClusterKey: edgeproto.ClusterKey{
			Name:         "testCluster",
			Organization: "testClusterOrg",
		},
		AppInstKey: edgeproto.AppInstKey{
			CloudletKey: edgeproto.CloudletKey{
				Name:         "testCloudlet",
				Organization: "testCloudletOrg",
			},
		},
	},
}
