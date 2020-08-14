package alertmgr

import (
	"strconv"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

var testSmtpInfo = smtpInfo{
	Email: "alerts@localhost",
	User:  "testuser",
	Token: "12345",
	Smtp:  "localhost",
	Port:  "25",
	Tls:   "false",
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
			cloudcommon.AlertHealthCheckStatus: strconv.Itoa(int(edgeproto.HealthCheck_HEALTH_CHECK_FAIL_ROOTLB_OFFLINE)),
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
			cloudcommon.AlertHealthCheckStatus: strconv.Itoa(int(edgeproto.HealthCheck_HEALTH_CHECK_FAIL_ROOTLB_OFFLINE)),
		},
	},
}

var testAlertReceivers = []ormapi.AlertReceiver{
	ormapi.AlertReceiver{
		Name:     "invalidReceiver",
		Type:     "invalidType",
		Severity: AlertSeverityError,
		User:     testUsers[0],
	},
	ormapi.AlertReceiver{
		Name:     "testorgemailreceiver",
		Type:     AlertReceiverTypeEmail,
		Severity: AlertSeverityError,
		User:     testUsers[0],
		AppInst: edgeproto.AppInstKey{
			AppKey: edgeproto.AppKey{
				Name:         "testApp",
				Organization: "testAppOrg",
				Version:      "v1.0",
			},
			ClusterInstKey: edgeproto.ClusterInstKey{
				ClusterKey: edgeproto.ClusterKey{
					Name: "testCluster",
				},
				CloudletKey: edgeproto.CloudletKey{
					Name:         "testCloudlet",
					Organization: "testCloudletOrg",
				},
				Organization: "testClusterOrg",
			},
		},
	},
}

var testAlertReceiverEmailCfg = ormapi.User{
	Name:  testUsers[0],
	Email: "testuser1@testorg.net",
}
