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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	client "github.com/influxdata/influxdb/client/v2"
	"github.com/labstack/echo/v4"
)

var AppInstCheckpointFields = []string{
	edgeproto.AppInstKeyTagName,
	edgeproto.AppInstKeyTagOrganization,
	edgeproto.CloudletKeyTagName,
	edgeproto.CloudletKeyTagOrganization,
	edgeproto.CloudletKeyTagFederatedOrganization,
	cloudcommon.MetricTagDeployment,
	cloudcommon.MetricTagFlavor,
	cloudcommon.MetricTagStatus,
}

var appUsageEventFields = []string{
	cloudcommon.MetricTagFlavor,
	cloudcommon.MetricTagDeployment,
	cloudcommon.MetricTagEvent,
	cloudcommon.MetricTagStatus,
}

var clusterCheckpointFields = []string{
	cloudcommon.MetricTagFlavor,
	cloudcommon.MetricTagStatus,
	cloudcommon.MetricTagNodeCount,
	cloudcommon.MetricTagIpAccess,
}

var clusterUsageEventFields = []string{
	cloudcommon.MetricTagFlavor,
	cloudcommon.MetricTagEvent,
	cloudcommon.MetricTagStatus,
	cloudcommon.MetricTagNodeCount,
	cloudcommon.MetricTagIpAccess,
}

var clusterDataColumns = []string{
	cloudcommon.MetricTagRegion,
	edgeproto.ClusterKeyTagName,
	edgeproto.ClusterKeyTagOrganization,
	edgeproto.CloudletKeyTagName,
	edgeproto.CloudletKeyTagOrganization,
	edgeproto.CloudletKeyTagFederatedOrganization,
	cloudcommon.MetricTagFlavor,
	cloudcommon.MetricTagNumNodes,
	cloudcommon.MetricTagIpAccess,
	cloudcommon.MetricTagStartTime,
	cloudcommon.MetricTagEndTime,
	cloudcommon.MetricTagDuration,
	cloudcommon.MetricTagNote,
}

var appInstDataColumns = []string{
	cloudcommon.MetricTagRegion,
	edgeproto.AppInstKeyTagName,
	edgeproto.AppInstKeyTagOrganization,
	edgeproto.CloudletKeyTagName,
	edgeproto.CloudletKeyTagOrganization,
	edgeproto.CloudletKeyTagFederatedOrganization,
	cloudcommon.MetricTagFlavor,
	cloudcommon.MetricTagDeployment,
	cloudcommon.MetricTagStartTime,
	cloudcommon.MetricTagEndTime,
	cloudcommon.MetricTagDuration,
	cloudcommon.MetricTagNote,
}

var usageInfluxDBT = `SELECT {{.Selector}} from {{.Measurement}}` +
	` WHERE time >='{{.StartTime}}'` +
	` AND time <= '{{.EndTime}}'` +
	`{{if .AppInstName}} AND "app"='{{.AppInstName}}'{{end}}` +
	`{{if .ClusterName}} AND "cluster"='{{.ClusterName}}'{{end}}` +
	`{{if .ApiCallerOrg}} AND "{{.OrgField}}"='{{.ApiCallerOrg}}'{{end}}` +
	`{{if .AppVersion}} AND "ver"='{{.AppVersion}}'{{end}}` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .CloudletOrg}} AND "cloudletorg"='{{.CloudletOrg}}'{{end}}` +
	`{{if .DeploymentType}} AND deployment = '{{.DeploymentType}}'{{end}}` +
	`{{if .CloudletList}} AND ({{.CloudletList}}){{end}}` +
	` order by time desc`

var usageInfluxDBTemplate *template.Template

type usageTracker struct {
	flavor     string
	time       time.Time
	nodecount  int64
	ipaccess   string
	deployment string
}

var usageTypeCluster = "cluster-usage"
var usageTypeAppInst = "appinst-usage"

func init() {
	usageInfluxDBTemplate = template.Must(template.New("influxquery").Parse(usageInfluxDBT))
}

func checkUsageCheckpointInterval() error {
	if serverConfig.UsageCheckpointInterval != cloudcommon.MonthlyInterval {
		_, err := time.ParseDuration(serverConfig.UsageCheckpointInterval)
		if err != nil {
			return fmt.Errorf("Invalid usageCheckpointInterval %s, error parsing into duration: %v", serverConfig.UsageCheckpointInterval, err)
		}
		return nil
	}
	return nil
}

// Get most recent checkpoint with respect to t
func prevCheckpoint(t time.Time) time.Time {
	if serverConfig.UsageCheckpointInterval == cloudcommon.MonthlyInterval {
		// cast to UTC to make sure we get the right month and year
		y, m, _ := t.UTC().Date()
		return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
	}
	dur, _ := time.ParseDuration(serverConfig.UsageCheckpointInterval)
	return t.Truncate(dur)
}

// This function sets start and end time separate from
func fillUsageTimeAndGetCmd(q *influxQueryArgs, tmpl *template.Template, start *time.Time, end *time.Time) string {
	// Figure out the start/end time range for the query
	if !start.IsZero() {
		buf, err := start.MarshalText()
		if err == nil {
			q.StartTime = string(buf)
		}
	}
	if !end.IsZero() {
		buf, err := end.MarshalText()
		if err == nil {
			q.EndTime = string(buf)
		}
	}
	if q.Measurement != "" {
		q.Measurement = addQuotesToMeasurementNames(q.Measurement)
	}
	// now that we know all the details of the query - build it
	buf := bytes.Buffer{}
	if err := tmpl.Execute(&buf, q); err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to run template", "tmpl", tmpl, "args", q, "error", err)
		return ""
	}
	return buf.String()
}

func GetClusterUsage(ctx context.Context, event *client.Response, checkpoint *client.Response, start, end time.Time, region string) (*ormapi.MetricData, error) {
	series := ormapi.MetricSeries{
		Name:    usageTypeCluster,
		Values:  make([][]interface{}, 0),
		Columns: clusterDataColumns,
	}
	usageRecords := ormapi.MetricData{
		Series: []ormapi.MetricSeries{series},
	}
	clusterTracker := make(map[edgeproto.ClusterInstKey]usageTracker)

	// check to see if the influx output is empty or invalid
	emptyEvents, err := isMeasurementOutputEmpty(event, cloudcommon.ClusterInstEvent)
	if err != nil {
		return nil, err
	}
	emptyCheckpoints, err := isMeasurementOutputEmpty(checkpoint, cloudcommon.ClusterInstCheckpoints)
	if err != nil {
		return nil, err
	}
	if emptyEvents && emptyCheckpoints {
		return &usageRecords, nil
	}

	// grab the checkpoints of clusters that are up
	if !emptyCheckpoints {
		for _, values := range checkpoint.Results[0].Series[0].Values {
			// format [timestamp cluster clusterorg cloudlet cloudletorg flavor status nodecount ipaccess]
			if len(values) != 9 {
				return nil, fmt.Errorf("Error parsing influx response")
			}
			timestamp, err := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[0]))
			if err != nil {
				return nil, fmt.Errorf("Unable to parse timestamp: %v", err)
			}
			cluster := fmt.Sprintf("%v", values[1])
			clusterorg := fmt.Sprintf("%v", values[2])
			cloudlet := fmt.Sprintf("%v", values[3])
			cloudletorg := fmt.Sprintf("%v", values[4])
			flavor := fmt.Sprintf("%v", values[5])
			status := fmt.Sprintf("%v", values[6])
			var nodecount int64
			if values[7] == nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Invalid data entry - nodecount is nil", "values", values)
				nodecount = 0
			} else {
				nodecount, err = values[7].(json.Number).Int64()
			}
			if err != nil {
				return nil, fmt.Errorf("Error trying to convert nodecount to int: %s", err)
			}
			ipaccess := fmt.Sprintf("%v", values[8])

			if status == cloudcommon.InstanceUp {
				newTracker := edgeproto.ClusterInstKey{
					ClusterKey: edgeproto.ClusterKey{
						Name:         cluster,
						Organization: clusterorg,
					},
					CloudletKey: edgeproto.CloudletKey{
						Organization: cloudletorg,
						Name:         cloudlet,
					},
				}
				clusterTracker[newTracker] = usageTracker{
					flavor:    flavor,
					time:      timestamp,
					nodecount: nodecount,
					ipaccess:  ipaccess,
				}
			}
		}
	}

	// these records are ordered from most recent, so iterate backwards
	if !emptyEvents {
		for i := len(event.Results[0].Series[0].Values) - 1; i >= 0; i-- {
			values := event.Results[0].Series[0].Values[i]
			// value should be of the format [timestamp cluster clusterorg cloudlet cloudletorg flavor event status nodecount ipaccess]
			if len(values) != 10 {
				return nil, fmt.Errorf("Error parsing influx response")
			}
			timestamp, err := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[0]))
			if err != nil {
				return nil, fmt.Errorf("Unable to parse timestamp: %v", err)
			}

			cluster := fmt.Sprintf("%v", values[1])
			clusterorg := fmt.Sprintf("%v", values[2])
			cloudlet := fmt.Sprintf("%v", values[3])
			cloudletorg := fmt.Sprintf("%v", values[4])
			cloudletfedorg := fmt.Sprintf("%v", values[5])
			flavor := fmt.Sprintf("%v", values[6])
			event := fmt.Sprintf("%v", values[7])
			status := fmt.Sprintf("%v", values[8])
			var nodecount int64
			if values[8] == nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Invalid data entry - nodecount is nil", "values", values)
				nodecount = 0
			} else {
				nodecount, err = values[8].(json.Number).Int64()
			}
			if err != nil {
				return nil, fmt.Errorf("Error trying to convert nodecount to int: %s", err)
			}
			ipaccess := fmt.Sprintf("%v", values[9])

			//if the timestamp is before start and its a down, then get rid of it in the cluster tracker
			//otherwise put it in the cluster tracker
			newKey := edgeproto.ClusterInstKey{
				ClusterKey: edgeproto.ClusterKey{
					Name:         cluster,
					Organization: clusterorg,
				},
				CloudletKey: edgeproto.CloudletKey{
					Name:                  cloudlet,
					Organization:          cloudletorg,
					FederatedOrganization: cloudletfedorg,
				},
			}
			tracker, ok := clusterTracker[newKey]
			if status == cloudcommon.InstanceUp {
				if !ok {
					newTracker := usageTracker{
						flavor:    flavor,
						time:      timestamp,
						nodecount: nodecount,
						ipaccess:  ipaccess,
					}
					clusterTracker[newKey] = newTracker
				}
			} else if status == cloudcommon.InstanceDown {
				if ok {
					if !timestamp.Before(start) {
						var starttime time.Time
						if tracker.time.Before(start) {
							starttime = start
						} else {
							starttime = tracker.time
						}
						duration := timestamp.Sub(starttime)
						newRecord := []interface{}{
							region,
							cluster,
							clusterorg,
							cloudlet,
							cloudletorg,
							cloudletfedorg,
							flavor,
							nodecount,
							ipaccess,
							starttime,
							timestamp, // endtime
							duration,
							event, // note
						}
						usageRecords.Series[0].Values = append(usageRecords.Series[0].Values, newRecord)
					}
					delete(clusterTracker, newKey)
				}
			} else {
				return nil, fmt.Errorf("Unexpected influx status: %s", status)
			}
		}
	}

	// anything still in the clusterTracker is a currently running clusterinst
	for k, v := range clusterTracker {
		var starttime time.Time
		if v.time.Before(start) {
			starttime = start
		} else {
			starttime = v.time
		}
		duration := end.Sub(starttime)

		newRecord := []interface{}{
			region,
			k.ClusterKey.Name,
			k.ClusterKey.Organization,
			k.CloudletKey.Name,
			k.CloudletKey.Organization,
			k.CloudletKey.FederatedOrganization,
			v.flavor,
			v.nodecount,
			v.ipaccess,
			starttime,
			end,
			duration,
			"Running",
		}
		usageRecords.Series[0].Values = append(usageRecords.Series[0].Values, newRecord)
	}

	return &usageRecords, nil
}

func GetAppUsage(event *client.Response, checkpoint *client.Response, start, end time.Time, region string) (*ormapi.MetricData, error) {
	series := ormapi.MetricSeries{
		Name:    usageTypeAppInst,
		Values:  make([][]interface{}, 0),
		Columns: appInstDataColumns,
	}
	usageRecords := ormapi.MetricData{
		Series: []ormapi.MetricSeries{series},
	}
	appTracker := make(map[edgeproto.AppInstKey]usageTracker)

	// check to see if the influx output is empty or invalid
	emptyEvents, err := isMeasurementOutputEmpty(event, cloudcommon.AppInstEvent)
	if err != nil {
		return nil, err
	}
	emptyCheckpoints, err := isMeasurementOutputEmpty(checkpoint, cloudcommon.AppInstCheckpoints)
	if err != nil {
		return nil, err
	}
	if emptyEvents && emptyCheckpoints {
		return &usageRecords, nil
	}

	// grab the checkpoints of appinsts that are up
	if !emptyCheckpoints {
		for _, values := range checkpoint.Results[0].Series[0].Values {
			// format [timestamp app ver cluster clusterorg cloudlet cloudletorg org deployment flavor status]
			if len(values) != 11 {
				return nil, fmt.Errorf("Error parsing influx response")
			}
			timestamp, err := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[0]))
			if err != nil {
				return nil, fmt.Errorf("Unable to parse timestamp: %v", err)
			}
			appinstname := fmt.Sprintf("%v", values[1])
			appinstorg := fmt.Sprintf("%v", values[2])
			cloudlet := fmt.Sprintf("%v", values[3])
			cloudletorg := fmt.Sprintf("%v", values[4])
			cloudletfedorg := fmt.Sprintf("%v", values[5])
			deployment := fmt.Sprintf("%v", values[6])
			flavor := fmt.Sprintf("%v", values[7])
			status := fmt.Sprintf("%v", values[8])

			if status == cloudcommon.InstanceUp {
				newTracker := edgeproto.AppInstKey{
					Name:         appinstname,
					Organization: appinstorg,
					CloudletKey: edgeproto.CloudletKey{
						Name:                  cloudlet,
						Organization:          cloudletorg,
						FederatedOrganization: cloudletfedorg,
					},
				}
				appTracker[newTracker] = usageTracker{
					flavor:     flavor,
					time:       timestamp,
					deployment: deployment,
				}
			}
		}
	}

	// these records are ordered from most recent, so iterate backwards
	if !emptyEvents {
		for i := len(event.Results[0].Series[0].Values) - 1; i >= 0; i-- {
			values := event.Results[0].Series[0].Values[i]
			// value should be of the format [timestamp app ver cluster clusterorg cloudlet cloudletorg apporg flavor deployment event status]
			if len(values) != 12 {
				return nil, fmt.Errorf("Error parsing influx response")
			}
			timestamp, err := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[0]))
			if err != nil {
				return nil, fmt.Errorf("Unable to parse timestamp: %v", err)
			}

			appinstname := fmt.Sprintf("%v", values[1])
			appinstorg := fmt.Sprintf("%v", values[2])
			cloudlet := fmt.Sprintf("%v", values[3])
			cloudletorg := fmt.Sprintf("%v", values[4])
			cloudletfedorg := fmt.Sprintf("%v", values[5])
			flavor := fmt.Sprintf("%v", values[6])
			deployment := fmt.Sprintf("%v", values[7])
			event := fmt.Sprintf("%v", values[8])
			status := fmt.Sprintf("%v", values[9])

			//if the timestamp is before start and its a down, then get rid of it in the cluster tracker
			//otherwise put it in the cluster tracker
			newKey := edgeproto.AppInstKey{
				Name:         appinstname,
				Organization: appinstorg,
				CloudletKey: edgeproto.CloudletKey{
					Name:                  cloudlet,
					Organization:          cloudletorg,
					FederatedOrganization: cloudletfedorg,
				},
			}
			tracker, ok := appTracker[newKey]
			if status == cloudcommon.InstanceUp {
				if !ok {
					newTracker := usageTracker{
						flavor:     flavor,
						time:       timestamp,
						deployment: deployment,
					}
					appTracker[newKey] = newTracker
				}
			} else if status == cloudcommon.InstanceDown {
				if ok {
					if !timestamp.Before(start) {
						var starttime time.Time
						if tracker.time.Before(start) {
							starttime = start
						} else {
							starttime = tracker.time
						}
						duration := timestamp.Sub(starttime)

						newRecord := []interface{}{
							region,
							appinstname,
							appinstorg,
							cloudlet,
							cloudletorg,
							cloudletfedorg,
							flavor,
							deployment,
							starttime,
							timestamp, // endtime
							duration,
							event, // note
						}
						usageRecords.Series[0].Values = append(usageRecords.Series[0].Values, newRecord)
					}
					delete(appTracker, newKey)
				}
			} else {
				return nil, fmt.Errorf("Unexpected influx status: %s", status)
			}
		}
	}

	// anything still in the appTracker is a currently running clusterinst
	for k, v := range appTracker {
		var starttime time.Time
		if v.time.Before(start) {
			starttime = start
		} else {
			starttime = v.time
		}
		duration := end.Sub(starttime)

		newRecord := []interface{}{
			region,
			k.Name,
			k.Organization,
			k.CloudletKey.Name,
			k.CloudletKey.Organization,
			k.CloudletKey.FederatedOrganization,
			v.flavor,
			v.deployment,
			starttime,
			end,
			duration,
			"Running",
		}
		usageRecords.Series[0].Values = append(usageRecords.Series[0].Values, newRecord)
	}

	return &usageRecords, nil
}

// Query is a template with a specific set of if/else
func ClusterCheckpointsQuery(obj *ormapi.RegionClusterInstUsage, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     cloudcommon.GetInfluxSelectFields(append(ClusterInstFields, clusterCheckpointFields...)),
		Measurement:  cloudcommon.ClusterInstCheckpoints,
		CloudletList: generateCloudletList(cloudletList),
		ClusterName:  obj.ClusterInst.ClusterKey.Name,
	}
	if obj.ClusterInst.ClusterKey.Organization != "" {
		arg.OrgField = edgeproto.ClusterKeyTagOrganization
		arg.ApiCallerOrg = obj.ClusterInst.ClusterKey.Organization
		arg.CloudletOrg = obj.ClusterInst.CloudletKey.Organization
	} else {
		arg.OrgField = edgeproto.CloudletKeyTagOrganization
		arg.ApiCallerOrg = obj.ClusterInst.CloudletKey.Organization
		arg.ClusterOrg = obj.ClusterInst.ClusterKey.Organization
	}
	// set endtime to start and back up starttime by a checkpoint interval to hit the most recent
	// checkpoint that occurred before startTime
	checkpointTime := prevCheckpoint(obj.StartTime)
	return fillUsageTimeAndGetCmd(&arg, usageInfluxDBTemplate, &checkpointTime, &checkpointTime)
}

func ClusterUsageEventsQuery(obj *ormapi.RegionClusterInstUsage, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     cloudcommon.GetInfluxSelectFields(append(ClusterInstFields, clusterUsageEventFields...)),
		Measurement:  cloudcommon.ClusterInstEvent,
		CloudletList: generateCloudletList(cloudletList),
		ClusterName:  obj.ClusterInst.ClusterKey.Name,
	}
	if obj.ClusterInst.ClusterKey.Organization != "" {
		arg.OrgField = edgeproto.ClusterKeyTagOrganization
		arg.ApiCallerOrg = obj.ClusterInst.ClusterKey.Organization
		arg.CloudletOrg = obj.ClusterInst.CloudletKey.Organization
	} else {
		arg.OrgField = edgeproto.CloudletKeyTagOrganization
		arg.ApiCallerOrg = obj.ClusterInst.CloudletKey.Organization
		arg.ClusterOrg = obj.ClusterInst.ClusterKey.Organization
	}
	queryStart := prevCheckpoint(obj.StartTime)
	return fillUsageTimeAndGetCmd(&arg, usageInfluxDBTemplate, &queryStart, &obj.EndTime)
}

func AppInstCheckpointsQuery(obj *ormapi.RegionAppInstUsage, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     cloudcommon.GetInfluxSelectFields(AppInstCheckpointFields),
		Measurement:  cloudcommon.AppInstCheckpoints,
		AppInstName:  k8smgmt.NormalizeName(obj.AppInst.Name),
		CloudletList: generateCloudletList(cloudletList),
	}
	if obj.AppInst.Organization != "" {
		arg.OrgField = edgeproto.AppInstKeyTagOrganization
		arg.ApiCallerOrg = obj.AppInst.Organization
		arg.CloudletOrg = obj.AppInst.CloudletKey.Organization
	} else {
		arg.OrgField = edgeproto.CloudletKeyTagOrganization
		arg.ApiCallerOrg = obj.AppInst.CloudletKey.Organization
		arg.AppInstOrg = obj.AppInst.Organization
	}
	if obj.VmOnly {
		arg.DeploymentType = cloudcommon.DeploymentTypeVM
	}
	// set endtime to start and back up starttime by a checkpoint interval to hit the most recent
	// checkpoint that occurred before startTime
	checkpointTime := prevCheckpoint(obj.StartTime)
	return fillUsageTimeAndGetCmd(&arg, usageInfluxDBTemplate, &checkpointTime, &checkpointTime)
}

func AppInstUsageEventsQuery(obj *ormapi.RegionAppInstUsage, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     cloudcommon.GetInfluxSelectFields(append(AppInstFields, appUsageEventFields...)),
		Measurement:  cloudcommon.AppInstEvent,
		AppInstName:  k8smgmt.NormalizeName(obj.AppInst.Name),
		CloudletList: generateCloudletList(cloudletList),
	}
	if obj.AppInst.Organization != "" {
		arg.OrgField = edgeproto.AppInstKeyTagOrganization
		arg.ApiCallerOrg = obj.AppInst.Organization
		arg.CloudletOrg = obj.AppInst.CloudletKey.Organization
	} else {
		arg.OrgField = edgeproto.CloudletKeyTagOrganization
		arg.ApiCallerOrg = obj.AppInst.CloudletKey.Organization
	}
	if obj.VmOnly {
		arg.DeploymentType = cloudcommon.DeploymentTypeVM
	}
	queryStart := prevCheckpoint(obj.StartTime)
	return fillUsageTimeAndGetCmd(&arg, usageInfluxDBTemplate, &queryStart, &obj.EndTime)
}

// Check if the response contains at least one value for the given measurement
func isMeasurementOutputEmpty(resp *client.Response, measurement string) (bool, error) {
	if resp == nil {
		return false, fmt.Errorf("Error processing nil response")
	}
	// check to see if the influx output is empty or invalid
	if len(resp.Results) == 0 || len(resp.Results[0].Series) == 0 {
		// empty, no event logs at all
		return true, nil
	} else if len(resp.Results) != 1 ||
		len(resp.Results[0].Series) != 1 ||
		len(resp.Results[0].Series[0].Values) == 0 ||
		len(resp.Results[0].Series[0].Values[0]) == 0 ||
		resp.Results[0].Series[0].Name != measurement {
		// should only be 1 series, the 'measurement' one
		return false, fmt.Errorf("Error parsing influx, unexpected format")
	}
	return false, nil
}

func GetEventAndCheckpoint(ctx context.Context, rc *InfluxDBContext, eventCmd, checkpointCmd string) (*client.Response, *client.Response, error) {
	var eventResponse, checkpointResponse *client.Response
	err := influxStream(ctx, rc, []string{cloudcommon.EventsDbName}, eventCmd, func(res interface{}) error {
		resp, ok := res.([]client.Result)
		if ok {
			eventResponse = &client.Response{Results: resp}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	err = influxStream(ctx, rc, []string{cloudcommon.EventsDbName}, checkpointCmd, func(res interface{}) error {
		resp, ok := res.([]client.Result)
		if ok {
			checkpointResponse = &client.Response{Results: resp}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if eventResponse == nil {
		return nil, nil, fmt.Errorf("unable to get event log")
	} else if checkpointResponse == nil {
		return nil, nil, fmt.Errorf("unable to get checkpoint log")
	} else {
		return eventResponse, checkpointResponse, nil
	}
}

// Common method to handle both app and cluster metrics
func GetUsageCommon(c echo.Context) error {
	var checkpointCmd, eventCmd string
	var usage *ormapi.MetricData
	rc := &InfluxDBContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.claims = claims
	ctx := ormutil.GetContext(c)

	if strings.HasSuffix(c.Path(), "usage/app") {
		in := ormapi.RegionAppInstUsage{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.AppInst.GetTags()); err != nil {
			return err
		}

		// start and end times must be specified
		if in.StartTime.IsZero() || in.EndTime.IsZero() {
			return fmt.Errorf("Both start and end times must be specified")
		}

		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.AppInst.Organization},
			ResourceAppAnalytics, []edgeproto.CloudletKey{in.AppInst.CloudletKey})
		if err != nil {
			return err
		}

		rc.region = in.Region

		eventCmd = AppInstUsageEventsQuery(&in, cloudletList)
		checkpointCmd = AppInstCheckpointsQuery(&in, cloudletList)

		eventResp, checkResp, err := GetEventAndCheckpoint(ctx, rc, eventCmd, checkpointCmd)
		if err != nil {
			return err
		}
		usage, err = GetAppUsage(eventResp, checkResp, in.StartTime, in.EndTime, in.Region)
		if err != nil {
			return err
		}
	} else if strings.HasSuffix(c.Path(), "usage/cluster") {
		in := ormapi.RegionClusterInstUsage{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.ClusterInst.GetTags()); err != nil {
			return err
		}

		// start and end times must be specified
		if in.StartTime.IsZero() || in.EndTime.IsZero() {
			return fmt.Errorf("Both start and end times must be specified")
		}

		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.ClusterInst.ClusterKey.Organization},
			ResourceClusterAnalytics, []edgeproto.CloudletKey{in.ClusterInst.CloudletKey})
		if err != nil {
			return err
		}

		rc.region = in.Region

		eventCmd = ClusterUsageEventsQuery(&in, cloudletList)
		checkpointCmd = ClusterCheckpointsQuery(&in, cloudletList)

		eventResp, checkResp, err := GetEventAndCheckpoint(ctx, rc, eventCmd, checkpointCmd)
		if err != nil {
			return err
		}
		usage, err = GetClusterUsage(ctx, eventResp, checkResp, in.StartTime, in.EndTime, in.Region)
		if err != nil {
			return err
		}
	} else {
		return echo.ErrNotFound
	}
	billingusage := ormapi.AllMetrics{
		Data: []ormapi.MetricData{},
	}
	if len(usage.Series[0].Values) != 0 {
		billingusage.Data = append(billingusage.Data, *usage)
	}
	return ormutil.SetReply(c, &billingusage)
}
