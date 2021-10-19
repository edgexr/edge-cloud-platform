package orm

import (
	"fmt"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ctrlclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormutil"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
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
		OrgField:     "cloudletorg",
		ApiCallerOrg: obj.CloudletPool.Organization,
		CloudletList: generateCloudletList(cloudletList),
	}
	if queryType == CLUSTER {
		arg.Measurement = EVENT_CLUSTERINST
		arg.Selector = strings.Join(append(ClusterFields, clusterUsageEventFields...), ",")
	} else if queryType == APPINST {
		arg.Measurement = EVENT_APPINST
		arg.Selector = strings.Join(append(AppFields, appUsageEventFields...), ",")
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
		OrgField:     "cloudletorg",
		ApiCallerOrg: obj.CloudletPool.Organization,
		CloudletList: generateCloudletList(cloudletList),
	}
	if queryType == CLUSTER {
		arg.Measurement = cloudcommon.ClusterInstCheckpoints
		arg.Selector = strings.Join(append(ClusterFields, clusterCheckpointFields...), ",")
	} else if queryType == APPINST {
		arg.Measurement = cloudcommon.AppInstCheckpoints
		arg.Selector = strings.Join(AppCheckpointFields, ",")
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
				cloudletList = append(cloudletList, cloudlet)
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
		clusterUsage, err := GetClusterUsage(eventResp, checkResp, in.StartTime, in.EndTime, in.Region)
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
			Data: []ormapi.MetricData{*clusterUsage, *appUsage},
		}
		return ormutil.SetReply(c, &usage)
	} else {
		return echo.ErrNotFound
	}
}
