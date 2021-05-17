package orm

import (
	"testing"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

var (
	testSingleAppFilter       = "(\"apporg\"='testOrg1' AND \"app\"='testapp1' AND \"ver\"='10' AND \"cloudlet\"='testCloudlet1') AND (cloudlet='testCloudlet1')"
	testSingleAppQueryDefTime = "SELECT mean(cpu) as cpu FROM \"appinst-cpu\" WHERE (" +
		testSingleAppFilter + ") " +
		"AND time >= '2019-12-31T13:01:00Z' AND time <= '2020-01-01T01:01:00Z' " +
		"group by time(7m12s),app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 100"
	testSingleAppQueryLastPoint = "SELECT cpu FROM \"appinst-cpu\" WHERE (" +
		testSingleAppFilter + ") " +
		"group by app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 1"
	testSingleApp = ormapi.RegionAppInstMetrics{
		Region: "test",
		AppInsts: []edgeproto.AppInstKey{
			edgeproto.AppInstKey{
				AppKey: edgeproto.AppKey{
					Organization: "testOrg1",
					Name:         "testApp1",
					Version:      "1.0",
				},
				ClusterInstKey: edgeproto.VirtualClusterInstKey{
					CloudletKey: edgeproto.CloudletKey{
						Name: "testCloudlet1",
					},
				},
			},
		},
	}
	testAppsFilter = "(\"apporg\"='testOrg1' AND \"app\"='testapp1' AND \"ver\"='10' AND \"clusterorg\"='testOrg1' AND \"cluster\"='testCluster1' AND \"cloudlet\"='testCloudlet1' AND \"cloudletorg\"='testCloudletOrg1') OR " +
		"(\"apporg\"='testOrg1' AND \"app\"='testapp2' AND \"ver\"='20' AND \"clusterorg\"='testOrg1' AND \"cluster\"='testCluster2' AND \"cloudlet\"='testCloudlet2' AND \"cloudletorg\"='testCloudletOrg2') " +
		"AND (cloudlet='testCloudlet1' OR cloudlet='testCloudlet2')"
	testAppsQueryDefTime = "SELECT last(sendBytes) as sendBytes,last(recvBytes) as recvBytes FROM \"appinst-network\" WHERE (" +
		testAppsFilter + ") " +
		"AND time >= '2019-12-31T13:01:00Z' AND time <= '2020-01-01T01:01:00Z' " +
		"group by time(7m12s),app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 100"
	testAppsQueryLastPoint = "SELECT sendBytes,recvBytes FROM \"appinst-network\" WHERE (" +
		testAppsFilter + ") " +
		"group by app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 1"
	testApps = ormapi.RegionAppInstMetrics{
		Region: "test",
		AppInsts: []edgeproto.AppInstKey{
			edgeproto.AppInstKey{ // 0
				AppKey: edgeproto.AppKey{
					Organization: "testOrg1",
					Name:         "testApp1",
					Version:      "1.0",
				},
				ClusterInstKey: edgeproto.VirtualClusterInstKey{
					Organization: "testOrg1",
					CloudletKey: edgeproto.CloudletKey{
						Name:         "testCloudlet1",
						Organization: "testCloudletOrg1",
					},
					ClusterKey: edgeproto.ClusterKey{
						Name: "testCluster1",
					},
				},
			},
			edgeproto.AppInstKey{ // 1
				AppKey: edgeproto.AppKey{
					Organization: "testOrg1",
					Name:         "testApp2",
					Version:      "2.0",
				},
				ClusterInstKey: edgeproto.VirtualClusterInstKey{
					Organization: "testOrg1",
					CloudletKey: edgeproto.CloudletKey{
						Name:         "testCloudlet2",
						Organization: "testCloudletOrg2",
					},
					ClusterKey: edgeproto.ClusterKey{
						Name: "testCluster2",
					},
				},
			},
		},
	}
)

func getCloudletsFromAppInsts(apps *ormapi.RegionAppInstMetrics) []string {
	cloudlets := []string{}
	for _, app := range apps.AppInsts {
		cloudlets = append(cloudlets, app.ClusterInstKey.CloudletKey.Name)
	}
	return cloudlets
}

func TestFillTimeAndGetCmd(t *testing.T) {
	// Single App, default time insterval
	testSingleApp.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	timeDef := getTimeDefinition(&testSingleApp)
	selectorFunction := getFuncForSelector("cpu", timeDef)
	args := influxQueryArgs{
		Selector:       getSelectorForMeasurement("cpu", selectorFunction),
		Measurement:    getMeasurementString("cpu", APPINST),
		QueryFilter:    getAppInstQueryFilter(&testSingleApp, getCloudletsFromAppInsts(&testSingleApp)),
		TimeDefinition: timeDef,
		Last:           testSingleApp.Last,
	}
	query := fillTimeAndGetCmd(&args, appInstGroupQueryTemplate, &testSingleApp.StartTime, &testSingleApp.EndTime)
	require.Equal(t, testSingleAppQueryDefTime, query)
	// Single App, just one last data points
	testSingleApp.EndTime = time.Time{}
	testSingleApp.StartTime = time.Time{}
	testSingleApp.Last = 1
	timeDef = getTimeDefinition(&testSingleApp)
	selectorFunction = getFuncForSelector("cpu", timeDef)
	args = influxQueryArgs{
		Selector:       getSelectorForMeasurement("cpu", selectorFunction),
		Measurement:    getMeasurementString("cpu", APPINST),
		QueryFilter:    getAppInstQueryFilter(&testSingleApp, getCloudletsFromAppInsts(&testSingleApp)),
		TimeDefinition: timeDef,
		Last:           testSingleApp.Last,
	}
	query = fillTimeAndGetCmd(&args, appInstGroupQueryTemplate, &testSingleApp.StartTime, &testSingleApp.EndTime)
	require.Equal(t, testSingleAppQueryLastPoint, query)
	// Multiple Apps, default time interval
	testApps.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testApps.StartTime = time.Time{}
	testApps.Last = 0
	timeDef = getTimeDefinition(&testApps)
	selectorFunction = getFuncForSelector("network", timeDef)
	args = influxQueryArgs{
		Selector:       getSelectorForMeasurement("network", selectorFunction),
		Measurement:    getMeasurementString("network", APPINST),
		QueryFilter:    getAppInstQueryFilter(&testApps, getCloudletsFromAppInsts(&testApps)),
		TimeDefinition: timeDef,
		Last:           testApps.Last,
	}
	query = fillTimeAndGetCmd(&args, appInstGroupQueryTemplate, &testApps.StartTime, &testApps.EndTime)
	require.Equal(t, testAppsQueryDefTime, query)
	// Multiple Apps, just one last data points
	testApps.EndTime = time.Time{}
	testApps.StartTime = time.Time{}
	testApps.Last = 1
	timeDef = getTimeDefinition(&testApps)
	selectorFunction = getFuncForSelector("network", timeDef)
	args = influxQueryArgs{
		Selector:       getSelectorForMeasurement("network", selectorFunction),
		Measurement:    getMeasurementString("network", APPINST),
		QueryFilter:    getAppInstQueryFilter(&testApps, getCloudletsFromAppInsts(&testApps)),
		TimeDefinition: timeDef,
		Last:           testApps.Last,
	}
	query = fillTimeAndGetCmd(&args, appInstGroupQueryTemplate, &testApps.StartTime, &testApps.EndTime)
	require.Equal(t, testAppsQueryLastPoint, query)

}

func TestGetAppInstQueryFilter(t *testing.T) {
	// Tests single app string
	require.Equal(t, testSingleAppFilter, getAppInstQueryFilter(&testSingleApp,
		getCloudletsFromAppInsts(&testSingleApp)))
	// Test query for multiple apps
	require.Equal(t, testAppsFilter, getAppInstQueryFilter(&testApps, getCloudletsFromAppInsts(&testApps)))
}

func TestGetFuncForSelector(t *testing.T) {
	require.Empty(t, getFuncForSelector("cpu", ""))
	require.Empty(t, getFuncForSelector("invalid", DefaultTimeWindow.String()))
	require.Equal(t, "mean", getFuncForSelector("cpu", DefaultTimeWindow.String()))
	require.Equal(t, "max", getFuncForSelector("mem", DefaultTimeWindow.String()))
	require.Equal(t, "max", getFuncForSelector("disk", DefaultTimeWindow.String()))
	require.Equal(t, "last", getFuncForSelector("network", DefaultTimeWindow.String()))
	require.Equal(t, "last", getFuncForSelector("connections", DefaultTimeWindow.String()))
	require.Equal(t, "last", getFuncForSelector("udp", DefaultTimeWindow.String()))
}

func TestGetSelectorForMeasurement(t *testing.T) {
	require.Equal(t, "invalid", getSelectorForMeasurement("invalid", ""))
	require.Equal(t, "invalid", getSelectorForMeasurement("invalid", "max"))
	// Single field selectors
	require.Equal(t, "cpu", getSelectorForMeasurement("cpu", ""))
	require.Equal(t, "max(cpu) as cpu", getSelectorForMeasurement("cpu", "max"))
	require.Equal(t, "mem", getSelectorForMeasurement("mem", ""))
	require.Equal(t, "max(mem) as mem", getSelectorForMeasurement("mem", "max"))
	require.Equal(t, "disk", getSelectorForMeasurement("disk", ""))
	require.Equal(t, "max(disk) as disk", getSelectorForMeasurement("disk", "max"))
	// mutli-field selectors
	require.Equal(t, "sendBytes,recvBytes", getSelectorForMeasurement("network", ""))
	require.Equal(t, "last(sendBytes) as sendBytes,last(recvBytes) as recvBytes",
		getSelectorForMeasurement("network", "last"))
	require.Equal(t, "port,active,handled,accepts,bytesSent,bytesRecvd,P0,P25,P50,P75,P90,P95,P99,\"P99.5\",\"P99.9\",P100",
		getSelectorForMeasurement("connections", ""))
	require.Equal(t, "last(port) as port,last(active) as active,last(handled) as handled,last(accepts) as accepts,last(bytesSent) as bytesSent,last(bytesRecvd) as bytesRecvd,last(P0) as P0,last(P25) as P25,last(P50) as P50,last(P75) as P75,last(P90) as P90,last(P95) as P95,last(P99) as P99,last(\"P99.5\") as \"P99.5\",last(\"P99.9\") as \"P99.9\",last(P100) as P100",
		getSelectorForMeasurement("connections", "last"))
}

func TestGetTimeDefinition(t *testing.T) {
	// With nothing set in testApps we look back 12hrs, so time definition will be 12hr/100 ~7m12s
	testApps.StartTime = time.Time{}
	testApps.EndTime = time.Time{}
	testApps.Last = 0
	require.Equal(t, "7m12s", getTimeDefinition(&testApps))
	require.Equal(t, MaxTimeDefinition, testApps.Last)
	// Reset time and set Last and nothing else
	testApps.StartTime = time.Time{}
	testApps.EndTime = time.Time{}
	testApps.Last = 12
	require.Empty(t, getTimeDefinition(&testApps))
	require.Equal(t, 12, testApps.Last)
	// invalid time range
	testApps.StartTime = time.Now()
	testApps.EndTime = time.Now().Add(-3 * time.Minute)
	testApps.Last = 12
	require.Empty(t, getTimeDefinition(&testApps))
	require.Equal(t, 12, testApps.Last)
	testApps.Last = 0
	require.Empty(t, getTimeDefinition(&testApps))
	require.Equal(t, MaxTimeDefinition, testApps.Last)
	// Check default time window of 15 secs
	testApps.StartTime = time.Now().Add(-2 * time.Minute)
	testApps.EndTime = time.Now()
	require.Equal(t, DefaultTimeWindow.String(), getTimeDefinition(&testApps))
	require.Equal(t, MaxTimeDefinition, testApps.Last)
}
