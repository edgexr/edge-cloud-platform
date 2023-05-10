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
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/labstack/echo/v4"
)

func generateCloudletList(cloudletList []string) string {
	if len(cloudletList) == 0 {
		return ""
	}
	// format needs to be: cloudlet='cloudlet1' OR cloudlet='cloudlet2' ... OR cloudlet='cloudlet3'
	new := strings.Join(cloudletList, "' OR cloudlet='")
	new = "cloudlet='" + new + "'"
	return new
}

// For Dme metrics cloudlets are stored in foundCloudlet field
func generateDmeApiUsageCloudletList(cloudletList []string) string {
	if len(cloudletList) == 0 {
		return ""
	}
	// format needs to be: foundCloudlet='cloudlet1' OR foundCloudlet='cloudlet2' ... OR foundCloudlet='cloudlet3'
	new := strings.Join(cloudletList, "' OR foundCloudlet='")
	new = "foundCloudlet='" + new + "'"
	return new
}

func cloudletPoolEventsQuery(obj *ormapi.RegionCloudletPoolUsage, cloudletList []string, queryType string) string {
	arg := influxQueryArgs{
		CloudletOrg:  obj.CloudletPool.Organization,
		CloudletList: generateCloudletList(cloudletList),
	}
	if queryType == CLUSTER {
		arg.Measurement = cloudcommon.ClusterInstEvent
		arg.Selector = cloudcommon.GetInfluxSelectFields(append(ClusterInstFields, clusterUsageEventFields...))
	} else if queryType == APPINST {
		arg.Measurement = cloudcommon.AppInstEvent
		arg.Selector = cloudcommon.GetInfluxSelectFields(append(AppInstFields, appUsageEventFields...))
		if obj.ShowVmAppsOnly {
			arg.DeploymentType = cloudcommon.DeploymentTypeVM
		}
	} else {
		return ""
	}
	queryStart := prevCheckpoint(obj.StartTime)
	return fillUsageTimeAndGetCmd(&arg, usageInfluxDBTemplate, &queryStart, &obj.EndTime)
}

func cloudletPoolCheckpointsQuery(obj *ormapi.RegionCloudletPoolUsage, cloudletList []string, queryType string) string {
	arg := influxQueryArgs{
		CloudletOrg:  obj.CloudletPool.Organization,
		CloudletList: generateCloudletList(cloudletList),
	}
	if queryType == CLUSTER {
		arg.Measurement = cloudcommon.ClusterInstCheckpoints
		arg.Selector = cloudcommon.GetInfluxSelectFields(append(ClusterInstFields, clusterCheckpointFields...))
	} else if queryType == APPINST {
		arg.Measurement = cloudcommon.AppInstCheckpoints
		arg.Selector = cloudcommon.GetInfluxSelectFields(AppInstCheckpointFields)
		if !obj.ShowVmAppsOnly {
			arg.DeploymentType = cloudcommon.DeploymentTypeVM
		}
	} else {
		return ""
	}
	// set endtime to start and back up starttime by a checkpoint interval to hit the most recent
	// checkpoint that occurred before startTime
	checkpointTime := prevCheckpoint(obj.StartTime)
	return fillUsageTimeAndGetCmd(&arg, usageInfluxDBTemplate, &checkpointTime, &checkpointTime)
}

func GetCloudletPoolUsageCommon(c echo.Context) error {
	rc := &InfluxDBContext{}
	regionRc := &ormutil.RegionContext{}

	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.claims = claims
	regionRc.Username = claims.Username
	regionRc.Database = database
	ctx := ormutil.GetContext(c)

	if strings.HasSuffix(c.Path(), "usage/cloudletpool") {
		in := ormapi.RegionCloudletPoolUsage{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.CloudletPool.GetTags()); err != nil {
			return err
		}

		// Operator and cloudletpool name has to be specified
		if in.CloudletPool.Organization == "" || in.CloudletPool.Name == "" {
			return fmt.Errorf("CloudletPool details must be present")
		}
		rc.region = in.Region
		regionRc.Region = in.Region

		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, in.CloudletPool.Organization, ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}

		cloudletpoolQuery := edgeproto.CloudletPool{Key: in.CloudletPool}
		// Auth check is already performed above
		regionRc.SkipAuthz = true
		cloudletList := []string{}
		err = ctrlclient.ShowCloudletPoolStream(ctx, regionRc, &cloudletpoolQuery, connCache, nil, func(pool *edgeproto.CloudletPool) error {
			for _, cloudlet := range pool.Cloudlets {
				cloudletList = append(cloudletList, cloudlet.Name)
			}
			return nil
		})
		if err != nil {
			return err
		}
		// check clusters
		eventCmd := cloudletPoolEventsQuery(&in, cloudletList, CLUSTER)
		checkpointCmd := cloudletPoolCheckpointsQuery(&in, cloudletList, CLUSTER)
		eventResp, checkResp, err := GetEventAndCheckpoint(ctx, rc, eventCmd, checkpointCmd)
		if err != nil {
			return fmt.Errorf("Error retrieving usage records: %v", err)
		}
		clusterUsage, err := GetClusterUsage(ctx, eventResp, checkResp, in.StartTime, in.EndTime, in.Region)
		if err != nil {
			return fmt.Errorf("Error calculating usage records: %v", err)
		}

		// check appinsts
		eventCmd = cloudletPoolEventsQuery(&in, cloudletList, APPINST)
		checkpointCmd = cloudletPoolCheckpointsQuery(&in, cloudletList, APPINST)
		eventResp, checkResp, err = GetEventAndCheckpoint(ctx, rc, eventCmd, checkpointCmd)
		if err != nil {
			return fmt.Errorf("Error retrieving usage records: %v", err)
		}
		appUsage, err := GetAppUsage(eventResp, checkResp, in.StartTime, in.EndTime, in.Region)
		if err != nil {
			return fmt.Errorf("Error calculating usage records: %v", err)
		}
		log.SpanLog(ctx, log.DebugLevelMetrics, "usage args", "cluster", clusterUsage, "app", appUsage, "list", cloudletList)

		usage := ormapi.AllMetrics{
			Data: []ormapi.MetricData{},
		}
		if len(clusterUsage.Series[0].Values) != 0 {
			usage.Data = append(usage.Data, *clusterUsage)
		}
		if len(appUsage.Series[0].Values) != 0 {
			usage.Data = append(usage.Data, *appUsage)
		}
		return ormutil.SetReply(c, &usage)
	} else {
		return echo.ErrNotFound
	}
}
