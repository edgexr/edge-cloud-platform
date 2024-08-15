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

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/gogo/protobuf/types"
)

type AppCheckpoint struct {
	Timestamp time.Time
	Org       string
	Keys      []*edgeproto.AppInstKey
	Status    []string // either cloudcommon.InstanceUp or cloudcommon.InstanceDown
}

// Returns a string of format `"selector"='%s' AND ...`
func getInfluxQueryWhere(selectors []string) string {
	qs := []string{}
	for _, selector := range selectors {
		q := `"` + selector + `"='%s'`
		qs = append(qs, q)
	}
	return strings.Join(qs, " AND ")
}

var AppUsageInfluxQueryTemplate = `SELECT %s from "%s" WHERE ` + getInfluxQueryWhere(cloudcommon.AppInstEventSelectors) + ` AND time >= '%s' AND time < '%s' order by time desc`

func (s *AppApi) CreateAppUsageRecord(ctx context.Context, appInst *edgeproto.AppInst, endTime time.Time) error {
	var metric *edgeproto.Metric
	// query from the checkpoint up to the event
	selectors := []string{
		cloudcommon.MetricTagEvent,
		cloudcommon.MetricTagStatus,
	}
	org := appInst.Key.Organization

	checkpoint, err := GetAppCheckpoint(ctx, org, endTime)
	if err != nil {
		return fmt.Errorf("unable to retrieve Checkpoint: %v", err)
	}
	influxLogQuery := fmt.Sprintf(AppUsageInfluxQueryTemplate,
		cloudcommon.GetInfluxSelectFields(selectors),
		cloudcommon.AppInstEvent,
		appInst.Key.Name,
		appInst.Key.Organization,
		appInst.CloudletKey.Name,
		appInst.CloudletKey.Organization,
		appInst.CloudletKey.FederatedOrganization,
		checkpoint.Timestamp.Format(time.RFC3339),
		endTime.Format(time.RFC3339))
	logs, err := services.events.QueryDB(influxLogQuery)
	if err != nil {
		return fmt.Errorf("Unable to query influx: %v", err)
	}

	stats := RunTimeStats{
		end: endTime,
	}
	err = GetRunTimeStats(usageTypeVmApp, *checkpoint, appInst.Key, logs, &stats)
	if err != nil {
		return err
	}

	// write the usage record to influx
	appInfo := edgeproto.App{}
	if !s.cache.Get(&appInst.AppKey, &appInfo) {
		return fmt.Errorf("Could not find appinst even though event log indicates it is up. App: %v", appInst.AppKey)
	}
	metric = createAppUsageMetric(appInst, &appInfo, stats.start, stats.end, stats.upTime, stats.status)

	services.events.AddMetric(metric)
	return nil
}

func createAppUsageMetric(appInst *edgeproto.AppInst, appInfo *edgeproto.App, startTime, endTime time.Time, runTime time.Duration, status string) *edgeproto.Metric {
	metric := edgeproto.Metric{}
	metric.Name = cloudcommon.AppInstCheckpoints
	ts, _ := types.TimestampProto(endTime)
	metric.Timestamp = *ts
	utc, _ := time.LoadLocation("UTC")
	//start and endtimes end up being put into different timezones somehow when going through calculations so force them both to the same here
	startUTC := startTime.In(utc)
	endUTC := endTime.In(utc)

	metric.AddKeyTags(&appInst.Key)
	metric.AddKeyTags(&appInst.ClusterKey)
	metric.AddKeyTags(&appInst.AppKey)
	metric.AddStringVal(cloudcommon.MetricTagDeployment, appInfo.Deployment)
	metric.AddStringVal(cloudcommon.MetricTagStart, startUTC.Format(time.RFC3339))
	metric.AddStringVal(cloudcommon.MetricTagEnd, endUTC.Format(time.RFC3339))
	metric.AddDoubleVal(cloudcommon.MetricTagUptime, runTime.Seconds())
	metric.AddStringVal(cloudcommon.MetricTagStatus, status)

	if appInfo.Deployment == cloudcommon.DeploymentTypeVM {
		metric.AddStringVal(cloudcommon.MetricTagFlavor, appInst.Flavor.Name)
	}

	return &metric
}

func appInstKeyFromMetricValues(values []interface{}) edgeproto.AppInstKey {
	appinst := fmt.Sprintf("%v", values[1])
	appinstorg := fmt.Sprintf("%v", values[2])
	key := edgeproto.AppInstKey{
		Name:         appinst,
		Organization: appinstorg,
	}
	return key
}

// This is checkpointing for all appinsts
func (s *AppApi) CreateAppCheckpoint(ctx context.Context, timestamp time.Time) error {
	if err := checkpointTimeValid(timestamp); err != nil { // we dont know if there will be more creates and deletes before the timestamp occurs
		return err
	}
	defer services.events.DoPush() // flush these right away for subsequent calls to GetAppCheckpoint
	// get all running appinsts and create a usage record of them

	selectors := append(cloudcommon.AppInstEventSelectors, cloudcommon.MetricTagEvent)
	influxLogQuery := fmt.Sprintf(CreateCheckpointInfluxQueryTemplate,
		cloudcommon.GetInfluxSelectFields(selectors),
		cloudcommon.AppInstEvent,
		PrevCheckpoint.Format(time.RFC3339),
		timestamp.Format(time.RFC3339))
	logs, err := services.events.QueryDB(influxLogQuery)
	if err != nil {
		return fmt.Errorf("Unable to query influx: %v", err)
	}

	empty, err := checkInfluxQueryOutput(logs, cloudcommon.AppInstEvent)
	skipLogCheck := false
	if err != nil {
		return err
	} else if empty {
		//there are no logs between endTime and the checkpoint, just copy over the checkpoint
		skipLogCheck = true
	}

	seenApps := make(map[edgeproto.AppInstKey]bool)
	if !skipLogCheck {
		for _, values := range logs[0].Series[0].Values {
			// value should be of the format [timestamp app apporg ver cluster clusterorg cloudlet cloudletorg event]
			if len(values) != len(selectors)+1 {
				return fmt.Errorf("Error parsing influx response")
			}
			key := appInstKeyFromMetricValues(values)
			event := cloudcommon.InstanceEvent(fmt.Sprintf("%v", values[6]))
			// only care about each appinsts most recent log
			if _, exists := seenApps[key]; exists {
				continue
			}
			seenApps[key] = true
			// if its still up, record it
			if event != cloudcommon.DELETED {
				appInst := edgeproto.AppInst{}
				if !s.all.appInstApi.cache.Get(&key, &appInst) {
					log.SpanLog(ctx, log.DebugLevelMetrics, "Could not find appinst even though event log indicates it is up", "app", key)
					continue
				}
				//record the usage up to this point
				err = s.CreateAppUsageRecord(ctx, &appInst, timestamp)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to create app usage record of checkpointed app", "app", key, "err", err)
				}
			}
		}
	}

	// check for apps that got checkpointed but did not have any log events between PrevCheckpoint and this one
	selectors = cloudcommon.AppInstEventSelectors
	influxCheckpointQuery := fmt.Sprintf(CreateCheckpointInfluxQueryTemplate,
		cloudcommon.GetInfluxSelectFields(selectors),
		cloudcommon.AppInstCheckpoints,
		PrevCheckpoint.Add(-1*time.Minute).Format(time.RFC3339), //small delta to account for conversion rounding inconsistencies
		PrevCheckpoint.Add(time.Minute).Format(time.RFC3339))
	checkpoints, err := services.events.QueryDB(influxCheckpointQuery)
	if err != nil {
		return fmt.Errorf("Unable to query influx: %v", err)
	}

	empty, err = checkInfluxQueryOutput(checkpoints, cloudcommon.AppInstCheckpoints)
	if err != nil {
		return err
	} else if empty {
		// no checkpoints made yet, or nothing got checkpointed last time, dont need to do this check
		return nil
	}

	for _, values := range checkpoints[0].Series[0].Values {
		// value should be of the format [timestamp app apporg ver cluster clusterorg cloudlet cloudletorg]
		if len(values) != len(selectors)+1 {
			return fmt.Errorf("Error parsing influx response")
		}
		key := appInstKeyFromMetricValues(values)
		if _, exists := seenApps[key]; exists {
			continue
		}
		seenApps[key] = true
		// record it
		info := edgeproto.AppInst{}
		if !s.all.appInstApi.cache.Get(&key, &info) {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Could not find appinst even though event log indicates it is up", "app", key)
			continue
		}
		err = s.CreateAppUsageRecord(ctx, &info, timestamp)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to create app usage record of checkpointed app", "app", key, "err", err)
		}
	}

	return nil
}

// returns all the checkpointed appinsts of the most recent checkpoint with regards to timestamp
func GetAppCheckpoint(ctx context.Context, org string, timestamp time.Time) (*AppCheckpoint, error) {
	// wait until the current checkpoint is done if we want to access it, to prevent race conditions with CreateCheckpoint
	for timestamp.After(NextCheckpoint) {
		time.Sleep(time.Second)
	}
	// query from the checkpoint up to the delete
	selectors := append(cloudcommon.AppInstEventSelectors,
		cloudcommon.MetricTagStatus,
		cloudcommon.MetricTagEnd,
	)
	influxCheckpointQuery := fmt.Sprintf(GetCheckpointInfluxQueryTemplate,
		cloudcommon.GetInfluxSelectFields(selectors),
		cloudcommon.AppInstCheckpoints,
		org,
		timestamp.Format(time.RFC3339))
	checkpoints, err := services.events.QueryDB(influxCheckpointQuery)
	if err != nil {
		return nil, fmt.Errorf("Unable to query influx: %v", err)
	}
	result := AppCheckpoint{
		Timestamp: PrevCheckpoint,
		Org:       org,
		Keys:      make([]*edgeproto.AppInstKey, 0),
		Status:    make([]string, 0),
	}

	empty, err := checkInfluxQueryOutput(checkpoints, cloudcommon.AppInstCheckpoints)
	if err != nil {
		return nil, err
	} else if empty {
		return &result, nil
	}

	for i, values := range checkpoints[0].Series[0].Values {
		// value should be of the format [timestamp app version cluster clusterorg cloudlet cloudletorg status]
		if len(values) != len(selectors)+1 {
			return nil, fmt.Errorf("Error parsing influx response")
		}
		key := appInstKeyFromMetricValues(values)
		status := fmt.Sprintf("%v", values[6])
		result.Keys = append(result.Keys, &key)
		result.Status = append(result.Status, status)

		measurementTime, err := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[7]))
		if err != nil {
			return nil, fmt.Errorf("unable to parse timestamp of checkpoint: %v", err)
		}

		if i == 0 {
			result.Timestamp = measurementTime
		} else { // all entries should have the same timestamp, if not equal, we ran through the whole checkpoint and moved onto an older one
			if !result.Timestamp.Equal(measurementTime) {
				break
			}
		}
	}
	return &result, nil
}
