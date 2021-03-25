package orm

import (
	"fmt"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
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
		if !obj.ShowNonVmApps {
			arg.DeploymentType = cloudcommon.DeploymentTypeVM
		}
	} else {
		return ""
	}
	queryStart := prevCheckpoint(obj.StartTime)
	return fillTimeAndGetCmd(&arg, usageInfluxDBTemplate, &queryStart, &obj.EndTime)
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
		if !obj.ShowNonVmApps {
			arg.DeploymentType = cloudcommon.DeploymentTypeVM
		}
	} else {
		return ""
	}
	// set endtime to start and back up starttime by a checkpoint interval to hit the most recent
	// checkpoint that occurred before startTime
	checkpointTime := prevCheckpoint(obj.StartTime)
	return fillTimeAndGetCmd(&arg, usageInfluxDBTemplate, &checkpointTime, &checkpointTime)
}

func GetCloudletPoolUsageCommon(c echo.Context) error {
	rc := &InfluxDBContext{}
	regionRc := &RegionContext{}

	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.claims = claims
	regionRc.username = claims.Username
	ctx := GetContext(c)

	if strings.HasSuffix(c.Path(), "usage/cloudletpool") {
		in := ormapi.RegionCloudletPoolUsage{}
		success, err := ReadConn(c, &in)
		if !success {
			return err
		}
		// Operator and cloudletpool name has to be specified
		if in.CloudletPool.Organization == "" || in.CloudletPool.Name == "" {
			return setReply(c, fmt.Errorf("CloudletPool details must be present"), nil)
		}
		rc.region = in.Region
		regionRc.region = in.Region

		cloudletpoolQuery := edgeproto.CloudletPool{Key: in.CloudletPool}
		// this also does an authorization check, so we dont have to
		cloudletPools, err := ShowCloudletPoolObj(ctx, regionRc, &cloudletpoolQuery)
		// since we specify name, should only have at most 1 result
		if err != nil {
			return err
		}
		if len(cloudletPools) != 1 {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Invalid response retrieving cloudletPool", "cloudletPools", cloudletPools)
			return setReply(c, fmt.Errorf("Unable to retrieve CloudletPool info"), nil)
		}

		cloudletList := []string{}
		for _, cloudlet := range cloudletPools[0].Cloudlets {
			cloudletList = append(cloudletList, cloudlet)
		}

		// check clusters
		eventCmd := cloudletPoolEventsQuery(&in, cloudletList, CLUSTER)
		checkpointCmd := cloudletPoolCheckpointsQuery(&in, cloudletList, CLUSTER)
		eventResp, checkResp, err := GetEventAndCheckpoint(ctx, rc, eventCmd, checkpointCmd)
		if err != nil {
			return setReply(c, fmt.Errorf("Error retrieving usage records: %v", err), nil)
		}
		clusterUsage, err := GetClusterUsage(eventResp, checkResp, in.StartTime, in.EndTime, in.Region)
		if err != nil {
			return setReply(c, fmt.Errorf("Error calculating usage records: %v", err), nil)
		}

		// check appinsts
		eventCmd = cloudletPoolEventsQuery(&in, cloudletList, APPINST)
		checkpointCmd = cloudletPoolCheckpointsQuery(&in, cloudletList, APPINST)
		eventResp, checkResp, err = GetEventAndCheckpoint(ctx, rc, eventCmd, checkpointCmd)
		if err != nil {
			return setReply(c, fmt.Errorf("Error retrieving usage records: %v", err), nil)
		}
		appUsage, err := GetAppUsage(eventResp, checkResp, in.StartTime, in.EndTime, in.Region)
		if err != nil {
			return setReply(c, fmt.Errorf("Error calculating usage records: %v", err), nil)
		}
		log.SpanLog(ctx, log.DebugLevelMetrics, "usage args", "cluster", clusterUsage, "app", appUsage, "list", cloudletList)

		usage := ormapi.AllMetrics{
			Data: []ormapi.MetricData{*clusterUsage, *appUsage},
		}
		if err != nil {
			return setReply(c, err, nil)
		}
		return setReply(c, nil, &usage)

	} else {
		return setReply(c, echo.ErrNotFound, nil)
	}
}
