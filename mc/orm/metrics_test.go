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

package orm

import (
	"strings"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/edgeproto"
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
	testSingleAppWildcardSelector = "SELECT cpu FROM \"appinst-cpu\" WHERE (" +
		testSingleAppFilter + ") " +
		"group by app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT mem FROM \"appinst-mem\" WHERE (" +
		testSingleAppFilter + ") " +
		"group by app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT disk FROM \"appinst-disk\" WHERE (" +
		testSingleAppFilter + ") " +
		"group by app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT sendBytes,recvBytes FROM \"appinst-network\" WHERE (" +
		testSingleAppFilter + ") " +
		"group by app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT port,active,handled,accepts,bytesSent,bytesRecvd,P0,P25,P50,P75,P90,P95,P99,\"P99.5\",\"P99.9\",P100 FROM \"appinst-connections\" WHERE (" +
		testSingleAppFilter + ") " +
		"group by app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT port,bytesSent,bytesRecvd,datagramsSent,datagramsRecvd,sentErrs,recvErrs,overflow,missed FROM \"appinst-udp\" WHERE (" +
		testSingleAppFilter + ") " +
		"group by app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg fill(previous) order by time desc limit 1"

	testSingleApp = appInstMetrics{
		RegionAppInstMetrics: &ormapi.RegionAppInstMetrics{
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
	testApps = appInstMetrics{
		RegionAppInstMetrics: &ormapi.RegionAppInstMetrics{
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
		},
	}

	testSingleClusterFilter       = "(\"clusterorg\"='testOrg1' AND \"cloudlet\"='testCloudlet1') AND (cloudlet='testCloudlet1')"
	testSingleClusterQueryDefTime = "SELECT mean(cpu) as cpu FROM \"cluster-cpu\" WHERE (" +
		testSingleClusterFilter + ") " +
		"AND time >= '2019-12-31T13:01:00Z' AND time <= '2020-01-01T01:01:00Z' " +
		"group by time(7m12s),cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 100"
	testSingleClusterQueryLastPoint = "SELECT cpu FROM \"cluster-cpu\" WHERE (" +
		testSingleClusterFilter + ") " +
		"group by cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 1"
	testSingleClusterWildcardSelector = "SELECT cpu FROM \"cluster-cpu\" WHERE (" +
		testSingleClusterFilter + ") " +
		"group by cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT mem FROM \"cluster-mem\" WHERE (" +
		testSingleClusterFilter + ") " +
		"group by cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT disk FROM \"cluster-disk\" WHERE (" +
		testSingleClusterFilter + ") " +
		"group by cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT sendBytes,recvBytes FROM \"cluster-network\" WHERE (" +
		testSingleClusterFilter + ") " +
		"group by cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT tcpConns,tcpRetrans FROM \"cluster-tcp\" WHERE (" +
		testSingleClusterFilter + ") " +
		"group by cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT udpSent,udpRecv,udpRecvErr FROM \"cluster-udp\" WHERE (" +
		testSingleClusterFilter + ") " +
		"group by cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc limit 1"

	testSingleCluster = clusterInstMetrics{
		RegionClusterInstMetrics: &ormapi.RegionClusterInstMetrics{
			Region: "test",
			ClusterInsts: []edgeproto.ClusterInstKey{
				edgeproto.ClusterInstKey{
					CloudletKey: edgeproto.CloudletKey{
						Name: "testCloudlet1",
					},
					Organization: "testOrg1",
				},
			},
		},
	}
	testClustersFilter = "(\"clusterorg\"='testOrg1' AND \"cluster\"='testCluster1' AND \"cloudlet\"='testCloudlet1' AND \"cloudletorg\"='testCloudletOrg1') OR " +
		"(\"clusterorg\"='testOrg2' AND \"cluster\"='testCluster2' AND \"cloudlet\"='testCloudlet2' AND \"cloudletorg\"='testCloudletOrg2') " +
		"AND (cloudlet='testCloudlet1' OR cloudlet='testCloudlet2')"
	testClustersQueryDefTime = "SELECT last(sendBytes) as sendBytes,last(recvBytes) as recvBytes FROM \"cluster-network\" WHERE (" +
		testClustersFilter + ") " +
		"AND time >= '2019-12-31T13:01:00Z' AND time <= '2020-01-01T01:01:00Z' " +
		"group by time(7m12s),cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 100"
	testClustersQueryLastPoint = "SELECT sendBytes,recvBytes FROM \"cluster-network\" WHERE (" +
		testClustersFilter + ") " +
		"group by cluster,clusterorg,cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 1"
	testClusters = clusterInstMetrics{
		RegionClusterInstMetrics: &ormapi.RegionClusterInstMetrics{
			Region: "test",
			ClusterInsts: []edgeproto.ClusterInstKey{
				edgeproto.ClusterInstKey{
					Organization: "testOrg1",
					CloudletKey: edgeproto.CloudletKey{
						Name:         "testCloudlet1",
						Organization: "testCloudletOrg1",
					},
					ClusterKey: edgeproto.ClusterKey{
						Name: "testCluster1",
					},
				},
				edgeproto.ClusterInstKey{
					Organization: "testOrg2",
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

	testSingleCloudletFilter       = "(\"cloudletorg\"='testCloudletOrg1' AND \"cloudlet\"='testCloudlet1')"
	testSingleCloudletQueryDefTime = "SELECT last(vCpuUsed) as vCpuUsed,last(vCpuMax) as vCpuMax,last(memUsed) as memUsed,last(memMax) as memMax,last(diskUsed) as diskUsed,last(diskMax) as diskMax " +
		"FROM \"cloudlet-utilization\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"AND time >= '2019-12-31T13:01:00Z' AND time <= '2020-01-01T01:01:00Z' " +
		"group by time(7m12s),cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 100"
	testSingleCloudletQueryLastPoint = "SELECT vCpuUsed,vCpuMax,memUsed,memMax,diskUsed,diskMax " +
		"FROM \"cloudlet-utilization\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 1"
	testSingleCloudletWildcardSelector = "SELECT netSend,netRecv FROM \"cloudlet-network\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT vCpuUsed,vCpuMax,memUsed,memMax,diskUsed,diskMax FROM \"cloudlet-utilization\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT floatingIpsUsed,floatingIpsMax,ipv4Used,ipv4Max FROM \"cloudlet-ipusage\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc limit 1"

	testSingleCloudlet = cloudletMetrics{
		RegionCloudletMetrics: &ormapi.RegionCloudletMetrics{
			Region: "test",
			Cloudlets: []edgeproto.CloudletKey{
				edgeproto.CloudletKey{
					Name:         "testCloudlet1",
					Organization: "testCloudletOrg1",
				},
			},
		},
	}
	testCloudletsFilter = "(\"cloudletorg\"='testCloudletOrg1' AND \"cloudlet\"='testCloudlet1') OR " +
		"(\"cloudletorg\"='testCloudletOrg2')"
	testCloudletsQueryDefTime = "SELECT last(netSend) as netSend,last(netRecv) as netRecv " +
		"FROM \"cloudlet-network\" WHERE (" +
		testCloudletsFilter + ") " +
		"AND time >= '2019-12-31T13:01:00Z' AND time <= '2020-01-01T01:01:00Z' " +
		"group by time(7m12s),cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 100"
	testCloudletsQueryLastPoint = "SELECT netSend,netRecv FROM \"cloudlet-network\" WHERE (" +
		testCloudletsFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 1"
	testCloudlets = cloudletMetrics{
		RegionCloudletMetrics: &ormapi.RegionCloudletMetrics{
			Region: "test",
			Cloudlets: []edgeproto.CloudletKey{
				edgeproto.CloudletKey{
					Name:         "testCloudlet1",
					Organization: "testCloudletOrg1",
				},
				edgeproto.CloudletKey{
					Organization: "testCloudletOrg2",
				},
			},
		},
	}

	testSingleCloudletUsageQueryDefTime = "SELECT last(vcpusUsed) as vcpusUsed,last(ramUsed) as ramUsed,last(instancesUsed) as instancesUsed,last(gpusUsed) as gpusUsed,last(externalIpsUsed) as externalIpsUsed,last(floatingIpsUsed) as floatingIpsUsed " +
		"FROM \"unittest-resource-usage\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"AND time >= '2019-12-31T13:01:00Z' AND time <= '2020-01-01T01:01:00Z' " +
		"group by time(7m12s),cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 100"
	testSingleCloudletUsageQueryLastPoint = "SELECT vcpusUsed,ramUsed,instancesUsed,gpusUsed,externalIpsUsed,floatingIpsUsed " +
		"FROM \"unittest-resource-usage\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 1"
	testSingleCloudletUsageWildcardSelector = "SELECT vcpusUsed,ramUsed,instancesUsed,gpusUsed,externalIpsUsed,floatingIpsUsed " +
		"FROM \"unittest-resource-usage\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc limit 1;" +
		"SELECT flavor,count " +
		"FROM \"flavorusage\" WHERE (" +
		testSingleCloudletFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc limit 1"
	testSingleCloudletUsage = cloudletUsageMetrics{
		cloudletMetrics: cloudletMetrics{
			RegionCloudletMetrics: &ormapi.RegionCloudletMetrics{
				Region: "test",
				Cloudlets: []edgeproto.CloudletKey{
					edgeproto.CloudletKey{
						Name:         "testCloudlet1",
						Organization: "testCloudletOrg1",
					},
				},
			},
		},
		platformTypes: map[string]struct{}{
			"unittest": struct{}{},
		},
	}

	testCloudletsUsageQueryDefTime = "SELECT last(flavor) as flavor,last(count) as count " +
		"FROM \"cloudlet-flavor-usage\" WHERE (" +
		testCloudletsFilter + ") " +
		"AND time >= '2019-12-31T13:01:00Z' AND time <= '2020-01-01T01:01:00Z' " +
		"group by time(7m12s),cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 100"
	testCloudletsUsageQueryLastPoint = "SELECT flavor,count " +
		"FROM \"cloudlet-flavor-usage\" WHERE (" +
		testCloudletsFilter + ") " +
		"group by cloudlet,cloudletorg fill(previous) order by time desc " +
		"limit 1"
	testCloudletsUsage = cloudletUsageMetrics{
		cloudletMetrics: cloudletMetrics{
			RegionCloudletMetrics: &ormapi.RegionCloudletMetrics{
				Region: "test",
				Cloudlets: []edgeproto.CloudletKey{
					edgeproto.CloudletKey{
						Name:         "testCloudlet1",
						Organization: "testCloudletOrg1",
					},
					edgeproto.CloudletKey{
						Organization: "testCloudletOrg2",
					},
				},
			},
		},
		platformTypes: map[string]struct{}{
			"unittest": struct{}{},
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

func getCloudletsFromClusterInsts(apps *ormapi.RegionClusterInstMetrics) []string {
	cloudlets := []string{}
	for _, cluster := range apps.ClusterInsts {
		cloudlets = append(cloudlets, cluster.CloudletKey.Name)
	}
	return cloudlets
}

func TestGetInfluxCloudletUsageMetricsQueryCmd(t *testing.T) {
	maxEntriesFromInfluxDb = 100
	// Single Cloudlets, default time interval
	testSingleCloudletUsage.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testSingleCloudletUsage.Selector = "resourceusage"
	err := validateAndResolveInfluxMetricsCommon(&testSingleCloudletUsage.MetricsCommon)
	require.Nil(t, err)
	timeDef := getTimeDefinition(testSingleCloudletUsage.GetMetricsCommon(), 0)
	args := getMetricsTemplateArgs(&testSingleCloudletUsage, timeDef, "resourceusage", nil)
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testSingleCloudletUsage.MetricsCommon, timeDef, 0)
	query := getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testSingleCloudletUsageQueryDefTime, query)
	// Single Cloudlet, just one last data points
	testSingleCloudletUsage.EndTime = time.Time{}
	testSingleCloudletUsage.StartTime = time.Time{}
	testSingleCloudletUsage.NumSamples = 0
	testSingleCloudletUsage.Limit = 1
	testSingleCloudletUsage.Selector = "resourceusage"
	err = validateAndResolveInfluxMetricsCommon(&testSingleCloudletUsage.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testSingleCloudletUsage.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testSingleCloudletUsage, timeDef, "resourceusage", nil)
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testSingleCloudletUsage.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testSingleCloudletUsageQueryLastPoint, query)
	// Multiple Cloudlets, default time interval
	testCloudletsUsage.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testCloudletsUsage.StartTime = time.Time{}
	testCloudletsUsage.Limit = 0
	testCloudletsUsage.NumSamples = 0
	testCloudletsUsage.Selector = "flavorusage"
	err = validateAndResolveInfluxMetricsCommon(&testCloudletsUsage.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testCloudletsUsage.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testCloudletsUsage, timeDef, "flavorusage", nil)
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testCloudletsUsage.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testCloudletsUsageQueryDefTime, query)
	// Multiple Cloudlets, just one last data points
	testCloudletsUsage.EndTime = time.Time{}
	testCloudletsUsage.StartTime = time.Time{}
	testCloudletsUsage.Limit = 1
	testCloudletsUsage.NumSamples = 0
	testCloudletsUsage.Selector = "flavorusage"
	err = validateAndResolveInfluxMetricsCommon(&testCloudletsUsage.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testCloudletsUsage.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testCloudletsUsage, timeDef, "flavorusage", nil)
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testCloudletsUsage.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testCloudletsUsageQueryLastPoint, query)
	// Test wildcard selector, single cloudlet
	testSingleCloudletUsage.EndTime = time.Time{}
	testSingleCloudletUsage.StartTime = time.Time{}
	testSingleCloudletUsage.NumSamples = 0
	testSingleCloudletUsage.Limit = 1
	testSingleCloudletUsage.Selector = "*"
	query = testSingleCloudletUsage.GetGroupQuery([]string{})
	require.Equal(t, testSingleCloudletUsageWildcardSelector, query)
}

func TestGetInfluxCloudletMetricsQueryCmd(t *testing.T) {
	maxEntriesFromInfluxDb = 100
	// Single Cloudlets, default time interval
	testSingleCloudlet.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testSingleCloudlet.Selector = "utilization"
	err := validateAndResolveInfluxMetricsCommon(&testSingleCloudlet.MetricsCommon)
	require.Nil(t, err)
	timeDef := getTimeDefinition(testSingleCloudlet.GetMetricsCommon(), 0)
	args := getMetricsTemplateArgs(&testSingleCloudlet, timeDef, "utilization", nil)
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testSingleCloudlet.MetricsCommon, timeDef, 0)
	query := getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testSingleCloudletQueryDefTime, query)
	// Single Cloudlet, just one last data points
	testSingleCloudlet.EndTime = time.Time{}
	testSingleCloudlet.StartTime = time.Time{}
	testSingleCloudlet.NumSamples = 0
	testSingleCloudlet.Limit = 1
	testSingleCloudlet.Selector = "utilization"
	err = validateAndResolveInfluxMetricsCommon(&testSingleCloudlet.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testSingleCloudlet.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testSingleCloudlet, timeDef, "utilization", nil)
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testSingleCloudlet.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testSingleCloudletQueryLastPoint, query)
	// Multiple Cloudlets, default time interval
	testCloudlets.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testCloudlets.StartTime = time.Time{}
	testCloudlets.Limit = 0
	testCloudlets.NumSamples = 0
	testCloudlets.Selector = "network"
	err = validateAndResolveInfluxMetricsCommon(&testCloudlets.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testCloudlets.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testCloudlets, timeDef, "network", nil)
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testCloudlets.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testCloudletsQueryDefTime, query)
	// Multiple Cloudlets, just one last data points
	testCloudlets.EndTime = time.Time{}
	testCloudlets.StartTime = time.Time{}
	testCloudlets.Limit = 1
	testCloudlets.NumSamples = 0
	testCloudlets.Selector = "network"
	err = validateAndResolveInfluxMetricsCommon(&testCloudlets.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testCloudlets.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testCloudlets, timeDef, "network", nil)
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testCloudlets.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testCloudletsQueryLastPoint, query)
	// Test wildcard selector, single cloudlet
	testSingleCloudlet.EndTime = time.Time{}
	testSingleCloudlet.StartTime = time.Time{}
	testSingleCloudlet.NumSamples = 0
	testSingleCloudlet.Limit = 1
	testSingleCloudlet.Selector = "*"
	query = testSingleCloudlet.GetGroupQuery([]string{})
	require.Equal(t, testSingleCloudletWildcardSelector, query)
}

func TestGetInfluxClusterMetricsQueryCmd(t *testing.T) {
	maxEntriesFromInfluxDb = 100
	// Single Cluster, default time interval
	testSingleCluster.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testSingleCluster.Selector = "cpu"
	err := validateAndResolveInfluxMetricsCommon(&testSingleCluster.MetricsCommon)
	require.Nil(t, err)
	timeDef := getTimeDefinition(testSingleCluster.GetMetricsCommon(), 0)
	args := getMetricsTemplateArgs(&testSingleCluster, timeDef, "cpu", getCloudletsFromClusterInsts(testSingleCluster.RegionClusterInstMetrics))
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testSingleCluster.MetricsCommon, timeDef, 0)
	query := getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testSingleClusterQueryDefTime, query)
	// Single Cluster, just one last data points
	testSingleCluster.EndTime = time.Time{}
	testSingleCluster.StartTime = time.Time{}
	testSingleCluster.NumSamples = 0
	testSingleCluster.Limit = 1
	testSingleCluster.Selector = "cpu"
	err = validateAndResolveInfluxMetricsCommon(&testSingleCluster.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testSingleCluster.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testSingleCluster, timeDef, "cpu", getCloudletsFromClusterInsts(testSingleCluster.RegionClusterInstMetrics))
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testSingleCluster.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testSingleClusterQueryLastPoint, query)
	// Multiple Clusters, default time interval
	testClusters.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testClusters.StartTime = time.Time{}
	testClusters.Limit = 0
	testClusters.NumSamples = 0
	testClusters.Selector = "network"
	err = validateAndResolveInfluxMetricsCommon(&testClusters.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testClusters.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testClusters, timeDef, "network", getCloudletsFromClusterInsts(testClusters.RegionClusterInstMetrics))
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testClusters.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testClustersQueryDefTime, query)
	// Multiple Clusters, just one last data points
	testClusters.EndTime = time.Time{}
	testClusters.StartTime = time.Time{}
	testClusters.Limit = 1
	testClusters.NumSamples = 0
	testClusters.Selector = "network"
	err = validateAndResolveInfluxMetricsCommon(&testClusters.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testClusters.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testClusters, timeDef, "network", getCloudletsFromClusterInsts(testClusters.RegionClusterInstMetrics))
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testClusters.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testClustersQueryLastPoint, query)
	// Wildcard check
	testSingleCluster.EndTime = time.Time{}
	testSingleCluster.StartTime = time.Time{}
	testSingleCluster.NumSamples = 0
	testSingleCluster.Limit = 1
	testSingleCluster.Selector = "*"
	query = testSingleCluster.GetGroupQuery([]string{"testCloudlet1"})
	require.Equal(t, testSingleClusterWildcardSelector, query)
}

func TestGetInfluxAppMetricsQueryCmd(t *testing.T) {
	maxEntriesFromInfluxDb = 100
	// Single App, default time insterval
	testSingleApp.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testSingleApp.Selector = "cpu"
	err := validateAndResolveInfluxMetricsCommon(&testSingleApp.MetricsCommon)
	require.Nil(t, err)
	timeDef := getTimeDefinition(testSingleApp.GetMetricsCommon(), 0)
	args := getMetricsTemplateArgs(&testSingleApp, timeDef, "cpu", getCloudletsFromAppInsts(testSingleApp.RegionAppInstMetrics))
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testSingleApp.MetricsCommon, timeDef, 0)
	query := getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testSingleAppQueryDefTime, query)
	// Single App, just one last data points
	testSingleApp.EndTime = time.Time{}
	testSingleApp.StartTime = time.Time{}
	testSingleApp.NumSamples = 0
	testSingleApp.Limit = 1
	testSingleApp.Selector = "cpu"
	err = validateAndResolveInfluxMetricsCommon(&testSingleApp.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testSingleApp.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testSingleApp, timeDef, "cpu", getCloudletsFromAppInsts(testSingleApp.RegionAppInstMetrics))
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testSingleApp.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testSingleAppQueryLastPoint, query)
	// Multiple Apps, default time interval
	testApps.EndTime = time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC)
	testApps.StartTime = time.Time{}
	testApps.Limit = 0
	testApps.NumSamples = 0
	testApps.Selector = "network"
	err = validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testApps.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testApps, timeDef, "network", getCloudletsFromAppInsts(testApps.RegionAppInstMetrics))
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testApps.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testAppsQueryDefTime, query)
	// Multiple Apps, just one last data points
	testApps.EndTime = time.Time{}
	testApps.StartTime = time.Time{}
	testApps.Limit = 1
	testApps.NumSamples = 0
	testApps.Selector = "network"
	err = validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.Nil(t, err)
	timeDef = getTimeDefinition(testApps.GetMetricsCommon(), 0)
	args = getMetricsTemplateArgs(&testApps, timeDef, "network", getCloudletsFromAppInsts(testApps.RegionAppInstMetrics))
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, &testApps.MetricsCommon, timeDef, 0)
	query = getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate)
	require.Equal(t, testAppsQueryLastPoint, query)
	// Wildcard check
	testSingleApp.EndTime = time.Time{}
	testSingleApp.StartTime = time.Time{}
	testSingleApp.NumSamples = 0
	testSingleApp.Limit = 1
	testSingleApp.Selector = "*"
	query = testSingleApp.GetGroupQuery([]string{"testCloudlet1"})
	require.Equal(t, testSingleAppWildcardSelector, query)
}

func TestGetAppInstQueryFilter(t *testing.T) {
	// Tests single app string
	require.Equal(t, testSingleAppFilter, testSingleApp.GetQueryFilter(getCloudletsFromAppInsts(testSingleApp.RegionAppInstMetrics)))
	// Test query for multiple apps
	require.Equal(t, testAppsFilter, testApps.GetQueryFilter(getCloudletsFromAppInsts(testApps.RegionAppInstMetrics)))
}

func TestGetClusterInstQueryFilter(t *testing.T) {
	// Tests single cluster string
	require.Equal(t, testSingleClusterFilter, testSingleCluster.GetQueryFilter(getCloudletsFromClusterInsts(testSingleCluster.RegionClusterInstMetrics)))
	// Test query for multiple clusters
	require.Equal(t, testClustersFilter, testClusters.GetQueryFilter(getCloudletsFromClusterInsts(testClusters.RegionClusterInstMetrics)))
}

func TestGetCloudletInstQueryFilter(t *testing.T) {
	// Tests single cloudlet string
	require.Equal(t, testSingleCloudletFilter, testSingleCloudlet.GetQueryFilter(nil))
	// Test query for multiple cloudlets
	require.Equal(t, testCloudletsFilter, testCloudlets.GetQueryFilter(nil))
}

func TestGetCloudletUsageInstQueryFilter(t *testing.T) {
	// Tests single cloudlet string - should be the same as for cloudlet metrics
	require.Equal(t, testSingleCloudletFilter, testSingleCloudletUsage.GetQueryFilter(nil))
	// Test query for multiple cloudlets - should be the same as for cloudlet metrics
	require.Equal(t, testCloudletsFilter, testCloudletsUsage.GetQueryFilter(nil))
}

func TestGetFuncForSelector(t *testing.T) {
	require.Empty(t, getFuncForSelector("cpu", ""))
	require.Empty(t, getFuncForSelector("invalid", DefaultAppInstTimeWindow.String()))
	require.Equal(t, "mean", getFuncForSelector("cpu", DefaultAppInstTimeWindow.String()))
	require.Equal(t, "max", getFuncForSelector("mem", DefaultAppInstTimeWindow.String()))
	require.Equal(t, "max", getFuncForSelector("disk", DefaultAppInstTimeWindow.String()))
	require.Equal(t, "last", getFuncForSelector("network", DefaultAppInstTimeWindow.String()))
	require.Equal(t, "last", getFuncForSelector("connections", DefaultAppInstTimeWindow.String()))
	require.Equal(t, "last", getFuncForSelector("udp", DefaultAppInstTimeWindow.String()))
}

func TestGetSelectorForMeasurement(t *testing.T) {
	require.Equal(t, "invalid", getSelectorForMeasurement("invalid", "", APPINST))
	require.Equal(t, "invalid", getSelectorForMeasurement("invalid", "max", APPINST))
	// Single field selectors
	require.Equal(t, "cpu", getSelectorForMeasurement("cpu", "", APPINST))
	require.Equal(t, "max(cpu) as cpu", getSelectorForMeasurement("cpu", "max", APPINST))
	require.Equal(t, "mem", getSelectorForMeasurement("mem", "", APPINST))
	require.Equal(t, "max(mem) as mem", getSelectorForMeasurement("mem", "max", APPINST))
	require.Equal(t, "disk", getSelectorForMeasurement("disk", "", APPINST))
	require.Equal(t, "max(disk) as disk", getSelectorForMeasurement("disk", "max", APPINST))
	// mutli-field selectors
	require.Equal(t, "sendBytes,recvBytes", getSelectorForMeasurement("network", "", APPINST))
	require.Equal(t, "last(sendBytes) as sendBytes,last(recvBytes) as recvBytes",
		getSelectorForMeasurement("network", "last", APPINST))
	require.Equal(t, strings.Join(CloudletNetworkFields, ","), getSelectorForMeasurement("network", "", CLOUDLET))
	require.Equal(t, "last(sendBytes) as sendBytes,last(recvBytes) as recvBytes",
		getSelectorForMeasurement("network", "last", APPINST))
	require.Equal(t, "last(netSend) as netSend,last(netRecv) as netRecv",
		getSelectorForMeasurement("network", "last", CLOUDLET))
	require.Equal(t, "port,active,handled,accepts,bytesSent,bytesRecvd,P0,P25,P50,P75,P90,P95,P99,\"P99.5\",\"P99.9\",P100",
		getSelectorForMeasurement("connections", "", APPINST))
	require.Equal(t, "last(port) as port,last(active) as active,last(handled) as handled,last(accepts) as accepts,last(bytesSent) as bytesSent,last(bytesRecvd) as bytesRecvd,last(P0) as P0,last(P25) as P25,last(P50) as P50,last(P75) as P75,last(P90) as P90,last(P95) as P95,last(P99) as P99,last(\"P99.5\") as \"P99.5\",last(\"P99.9\") as \"P99.9\",last(P100) as P100",
		getSelectorForMeasurement("connections", "last", APPINST))
	require.Equal(t, strings.Join(appUdpFields, ","), getSelectorForMeasurement("udp", "", APPINST))
	require.Equal(t, strings.Join(UdpFields, ","), getSelectorForMeasurement("udp", "", CLUSTER))
}

func TestGetTimeDefinition(t *testing.T) {
	maxEntriesFromInfluxDb = 100
	// Invalid start end age
	testApps.StartTime = time.Time{}
	testApps.EndTime = time.Time{}
	testApps.StartAge = edgeproto.Duration(time.Second)
	testApps.EndAge = edgeproto.Duration(2 * time.Second)
	testApps.Limit = 0
	err := validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.NotNil(t, err)
	require.Equal(t, "start age must be before (older than) end age", err.Error())
	// With nothing set in testApps we get last 100 data points
	testApps.StartTime = time.Time{}
	testApps.EndTime = time.Time{}
	testApps.Limit = 0
	err = validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.Nil(t, err)
	require.Equal(t, "", getTimeDefinition(&testApps.MetricsCommon, 0))
	require.Equal(t, maxEntriesFromInfluxDb, testApps.Limit)
	// With end time set to now we look back 12hrs, so time definition will be 12hr/100 ~7m12s
	testApps.StartTime = time.Time{}
	testApps.EndTime = time.Now()
	testApps.Limit = 0
	err = validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.Nil(t, err)
	require.Equal(t, "7m12s", getTimeDefinition(&testApps.MetricsCommon, 0))
	require.Equal(t, maxEntriesFromInfluxDb, testApps.NumSamples)
	// Reset time and set Last and nothing else
	testApps.StartTime = time.Time{}
	testApps.EndTime = time.Time{}
	testApps.NumSamples = 0
	testApps.Limit = 12
	err = validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.Nil(t, err)
	require.Empty(t, getTimeDefinition(&testApps.MetricsCommon, 0))
	require.Equal(t, 12, testApps.Limit)
	// invalid time range
	testApps.StartTime = time.Now()
	testApps.EndTime = time.Now().Add(-3 * time.Minute)
	testApps.NumSamples = 12
	testApps.Limit = 0
	err = validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.NotNil(t, err)
	require.Empty(t, getTimeDefinition(&testApps.MetricsCommon, 0))
	require.Equal(t, 12, testApps.NumSamples)
	testApps.Limit = 0
	testApps.NumSamples = 0
	err = validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.NotNil(t, err)
	require.Empty(t, getTimeDefinition(&testApps.MetricsCommon, 0))
	require.Equal(t, maxEntriesFromInfluxDb, testApps.NumSamples)
	// Check default time window of 15 secs
	testApps.StartTime = time.Now().Add(-2 * time.Minute)
	testApps.EndTime = time.Now()
	err = validateAndResolveInfluxMetricsCommon(&testApps.MetricsCommon)
	require.Nil(t, err)
	require.Equal(t, DefaultAppInstTimeWindow.String(), getTimeDefinition(&testApps.MetricsCommon, DefaultAppInstTimeWindow))
	require.Equal(t, maxEntriesFromInfluxDb, testApps.NumSamples)
}
