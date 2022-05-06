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

	client "github.com/influxdata/influxdb/client/v2"
	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
)

var AppCheckpointFields = []string{
	"\"app\"",
	"\"ver\"",
	"\"cluster\"",
	"\"clusterorg\"",
	"\"cloudlet\"",
	"\"cloudletorg\"",
	"\"org\"",
	"\"deployment\"",
	"\"flavor\"",
	"\"status\"",
}

var appUsageEventFields = []string{
	"\"flavor\"",
	"\"deployment\"",
	"\"event\"",
	"\"status\"",
}

var clusterCheckpointFields = []string{
	"\"flavor\"",
	"\"status\"",
	"\"nodecount\"",
	"\"ipaccess\"",
}

var clusterUsageEventFields = []string{
	"\"flavor\"",
	"\"event\"",
	"\"status\"",
	"\"nodecount\"",
	"\"ipaccess\"",
}

var clusterDataColumns = []string{
	"region",
	"cluster",
	"clusterorg",
	"cloudlet",
	"cloudletorg",
	"flavor",
	"numnodes",
	"ipaccess",
	"startime",
	"endtime",
	"duration",
	"note",
}

var appInstDataColumns = []string{
	"region",
	"app",
	"apporg",
	"version",
	"cluster",
	"clusterorg",
	"cloudlet",
	"cloudletorg",
	"flavor",
	"deployment",
	"startime",
	"endtime",
	"duration",
	"note",
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
	emptyEvents, err := isMeasurementOutputEmpty(event, EVENT_CLUSTERINST)
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
					ClusterKey: edgeproto.ClusterKey{Name: cluster},
					CloudletKey: edgeproto.CloudletKey{
						Organization: cloudletorg,
						Name:         cloudlet,
					},
					Organization: clusterorg,
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
			flavor := fmt.Sprintf("%v", values[5])
			event := fmt.Sprintf("%v", values[6])
			status := fmt.Sprintf("%v", values[7])
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
				ClusterKey: edgeproto.ClusterKey{Name: cluster},
				CloudletKey: edgeproto.CloudletKey{
					Organization: cloudletorg,
					Name:         cloudlet,
				},
				Organization: clusterorg,
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
			k.Organization,
			k.CloudletKey.Name,
			k.CloudletKey.Organization,
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
	emptyEvents, err := isMeasurementOutputEmpty(event, EVENT_APPINST)
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
			app := fmt.Sprintf("%v", values[1])
			ver := fmt.Sprintf("%v", values[2])
			cluster := fmt.Sprintf("%v", values[3])
			clusterorg := fmt.Sprintf("%v", values[4])
			cloudlet := fmt.Sprintf("%v", values[5])
			cloudletorg := fmt.Sprintf("%v", values[6])
			org := fmt.Sprintf("%v", values[7])
			deployment := fmt.Sprintf("%v", values[8])
			flavor := fmt.Sprintf("%v", values[9])
			status := fmt.Sprintf("%v", values[10])

			if status == cloudcommon.InstanceUp {
				newTracker := edgeproto.AppInstKey{
					AppKey: edgeproto.AppKey{
						Name:         app,
						Version:      ver,
						Organization: org,
					},
					ClusterInstKey: edgeproto.VirtualClusterInstKey{
						ClusterKey: edgeproto.ClusterKey{Name: cluster},
						CloudletKey: edgeproto.CloudletKey{
							Organization: cloudletorg,
							Name:         cloudlet,
						},
						Organization: clusterorg,
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

			app := fmt.Sprintf("%v", values[1])
			ver := fmt.Sprintf("%v", values[2])
			cluster := fmt.Sprintf("%v", values[3])
			clusterorg := fmt.Sprintf("%v", values[4])
			cloudlet := fmt.Sprintf("%v", values[5])
			cloudletorg := fmt.Sprintf("%v", values[6])
			apporg := fmt.Sprintf("%v", values[7])
			flavor := fmt.Sprintf("%v", values[8])
			deployment := fmt.Sprintf("%v", values[9])
			event := fmt.Sprintf("%v", values[10])
			status := fmt.Sprintf("%v", values[11])

			//if the timestamp is before start and its a down, then get rid of it in the cluster tracker
			//otherwise put it in the cluster tracker
			newKey := edgeproto.AppInstKey{
				AppKey: edgeproto.AppKey{
					Name:         app,
					Version:      ver,
					Organization: apporg,
				},
				ClusterInstKey: edgeproto.VirtualClusterInstKey{
					ClusterKey: edgeproto.ClusterKey{Name: cluster},
					CloudletKey: edgeproto.CloudletKey{
						Organization: cloudletorg,
						Name:         cloudlet,
					},
					Organization: clusterorg,
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
							app,
							apporg,
							ver,
							cluster,
							clusterorg,
							cloudlet,
							cloudletorg,
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
			k.AppKey.Name,
			k.AppKey.Organization,
			k.AppKey.Version,
			k.ClusterInstKey.ClusterKey.Name,
			k.ClusterInstKey.Organization,
			k.ClusterInstKey.CloudletKey.Name,
			k.ClusterInstKey.CloudletKey.Organization,
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
		Selector:     strings.Join(append(ClusterFields, clusterCheckpointFields...), ","),
		Measurement:  cloudcommon.ClusterInstCheckpoints,
		CloudletList: generateCloudletList(cloudletList),
		ClusterName:  obj.ClusterInst.ClusterKey.Name,
	}
	if obj.ClusterInst.Organization != "" {
		arg.OrgField = "clusterorg"
		arg.ApiCallerOrg = obj.ClusterInst.Organization
		arg.CloudletOrg = obj.ClusterInst.CloudletKey.Organization
	} else {
		arg.OrgField = "cloudletorg"
		arg.ApiCallerOrg = obj.ClusterInst.CloudletKey.Organization
		arg.ClusterOrg = obj.ClusterInst.Organization
	}
	// set endtime to start and back up starttime by a checkpoint interval to hit the most recent
	// checkpoint that occurred before startTime
	checkpointTime := prevCheckpoint(obj.StartTime)
	return fillUsageTimeAndGetCmd(&arg, usageInfluxDBTemplate, &checkpointTime, &checkpointTime)
}

func ClusterUsageEventsQuery(obj *ormapi.RegionClusterInstUsage, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     strings.Join(append(ClusterFields, clusterUsageEventFields...), ","),
		Measurement:  EVENT_CLUSTERINST,
		CloudletList: generateCloudletList(cloudletList),
		ClusterName:  obj.ClusterInst.ClusterKey.Name,
	}
	if obj.ClusterInst.Organization != "" {
		arg.OrgField = "clusterorg"
		arg.ApiCallerOrg = obj.ClusterInst.Organization
		arg.CloudletOrg = obj.ClusterInst.CloudletKey.Organization
	} else {
		arg.OrgField = "cloudletorg"
		arg.ApiCallerOrg = obj.ClusterInst.CloudletKey.Organization
		arg.ClusterOrg = obj.ClusterInst.Organization
	}
	queryStart := prevCheckpoint(obj.StartTime)
	return fillUsageTimeAndGetCmd(&arg, usageInfluxDBTemplate, &queryStart, &obj.EndTime)
}

func AppInstCheckpointsQuery(obj *ormapi.RegionAppInstUsage, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     strings.Join(AppCheckpointFields, ","),
		Measurement:  cloudcommon.AppInstCheckpoints,
		AppInstName:  k8smgmt.NormalizeName(obj.AppInst.AppKey.Name),
		AppVersion:   obj.AppInst.AppKey.Version,
		CloudletList: generateCloudletList(cloudletList),
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
		ClusterOrg:   obj.AppInst.ClusterInstKey.Organization,
	}
	if obj.AppInst.AppKey.Organization != "" {
		arg.OrgField = "apporg"
		arg.ApiCallerOrg = obj.AppInst.AppKey.Organization
		arg.CloudletOrg = obj.AppInst.ClusterInstKey.CloudletKey.Organization
	} else {
		arg.OrgField = "cloudletorg"
		arg.ApiCallerOrg = obj.AppInst.ClusterInstKey.CloudletKey.Organization
		arg.AppOrg = obj.AppInst.AppKey.Organization
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
		Selector:     strings.Join(append(AppFields, appUsageEventFields...), ","),
		Measurement:  EVENT_APPINST,
		AppInstName:  k8smgmt.NormalizeName(obj.AppInst.AppKey.Name),
		AppVersion:   obj.AppInst.AppKey.Version,
		CloudletList: generateCloudletList(cloudletList),
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
		ClusterOrg:   obj.AppInst.ClusterInstKey.Organization,
	}
	if obj.AppInst.AppKey.Organization != "" {
		arg.OrgField = "apporg"
		arg.ApiCallerOrg = obj.AppInst.AppKey.Organization
		arg.CloudletOrg = obj.AppInst.ClusterInstKey.CloudletKey.Organization
	} else {
		arg.OrgField = "cloudletorg"
		arg.ApiCallerOrg = obj.AppInst.ClusterInstKey.CloudletKey.Organization
		arg.AppOrg = obj.AppInst.AppKey.Organization
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

		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.AppInst.AppKey.Organization},
			ResourceAppAnalytics, []edgeproto.CloudletKey{in.AppInst.ClusterInstKey.CloudletKey})
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

		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.ClusterInst.Organization},
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
