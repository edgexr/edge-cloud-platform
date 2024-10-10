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
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/gogo/protobuf/types"
)

type ClusterCheckpoint struct {
	Timestamp time.Time
	Org       string
	Keys      []*edgeproto.ClusterKey
	Status    []string // either cloudcommon.InstanceUp or cloudcommon.InstanceDown
}

var ClusterUsageInfluxQueryTemplate = `SELECT %s from "%s" WHERE ` + getInfluxQueryWhere(cloudcommon.ClusterInstEventSelectors) + ` %sAND time >= '%s' AND time < '%s' order by time desc`

func (s *ClusterInstApi) CreateClusterUsageRecord(ctx context.Context, cluster *edgeproto.ClusterInst, endTime time.Time) error {
	var metric *edgeproto.Metric
	// query from the checkpoint up to the event
	selectors := []string{"event", "status"}
	reservedByOption := ""
	org := cluster.Key.Organization
	if edgeproto.IsEdgeCloudOrg(cluster.Key.Organization) && cluster.ReservedBy != "" {
		reservedByOption = fmt.Sprintf(`AND "reservedBy"='%s' `, cluster.ReservedBy)
		org = cluster.ReservedBy
	}
	checkpoint, err := GetClusterCheckpoint(ctx, org, endTime)
	if err != nil {
		return fmt.Errorf("unable to retrieve Checkpoint: %v", err)
	}
	influxLogQuery := fmt.Sprintf(ClusterUsageInfluxQueryTemplate,
		cloudcommon.GetInfluxSelectFields(selectors),
		cloudcommon.ClusterInstEvent,
		cluster.Key.Name,
		cluster.Key.Organization,
		cluster.CloudletKey.Name,
		cluster.CloudletKey.Organization,
		cluster.CloudletKey.FederatedOrganization,
		reservedByOption,
		checkpoint.Timestamp.Format(time.RFC3339),
		endTime.Format(time.RFC3339))
	logs, err := services.events.QueryDB(influxLogQuery)
	if err != nil {
		return fmt.Errorf("Unable to query influx: %v", err)
	}

	stats := RunTimeStats{
		end: endTime,
	}
	err = GetRunTimeStats(usageTypeCluster, *checkpoint, cluster.Key, logs, &stats)
	if err != nil {
		return err
	}

	// write the usage record to influx
	metric = s.createClusterUsageMetric(cluster, stats.start, stats.end, stats.upTime, stats.status)

	services.events.AddMetric(metric)
	return nil
}

func (s *ClusterInstApi) createClusterUsageMetric(cluster *edgeproto.ClusterInst, startTime, endTime time.Time, runTime time.Duration, status string) *edgeproto.Metric {
	metric := edgeproto.Metric{}
	metric.Name = cloudcommon.ClusterInstCheckpoints
	ts, _ := types.TimestampProto(endTime)
	metric.Timestamp = *ts
	utc, _ := time.LoadLocation("UTC")
	//start and endtimes end up being put into different timezones somehow when going through calculations so force them both to the same here
	startUTC := startTime.In(utc)
	endUTC := endTime.In(utc)

	resInfo := s.sumRequestedClusterResources(cluster)

	metric.AddKeyTags(&cluster.Key)
	metric.AddIntVal(cloudcommon.MetricTagRAM, resInfo.GetInt(cloudcommon.ResourceRamMb))
	metric.AddIntVal(cloudcommon.MetricTagVCPU, resInfo.GetInt(cloudcommon.ResourceVcpus))
	metric.AddIntVal(cloudcommon.MetricTagDisk, resInfo.GetInt(cloudcommon.ResourceDiskGb))
	metric.AddIntVal(cloudcommon.MetricTagGPUs, resInfo.GetInt(cloudcommon.ResourceGpus))
	metric.AddIntVal(cloudcommon.MetricTagNodeCount, resInfo.GetInt(cloudcommon.ResourceInstances))
	metric.AddStringVal(cloudcommon.MetricTagIpAccess, cluster.IpAccess.String())
	metric.AddStringVal("start", startUTC.Format(time.RFC3339))
	metric.AddStringVal("end", endUTC.Format(time.RFC3339))
	metric.AddDoubleVal("uptime", runTime.Seconds())
	if cluster.ReservedBy != "" && edgeproto.IsEdgeCloudOrg(cluster.Key.Organization) {
		metric.AddTag("org", cluster.ReservedBy)
	} else {
		metric.AddTag("org", cluster.Key.Organization)
	}
	metric.AddStringVal("status", status)
	return &metric
}

func clusterKeyFromMetricValues(values []interface{}) edgeproto.ClusterKey {
	cluster := fmt.Sprintf("%v", values[1])
	clusterorg := fmt.Sprintf("%v", values[2])
	key := edgeproto.ClusterKey{
		Name:         cluster,
		Organization: clusterorg,
	}
	return key
}

// This is checkpointing for the usage api, from month to month
func (s *ClusterInstApi) CreateClusterCheckpoint(ctx context.Context, timestamp time.Time) error {
	if err := checkpointTimeValid(timestamp); err != nil { // we dont know if there will be more creates and deletes before the timestamp occurs
		return err
	}
	defer services.events.DoPush() // flush these right away for subsequent calls to GetClusterCheckpoint
	// get all running clusterinsts and create a usage record of them
	selectors := append(cloudcommon.ClusterInstEventSelectors, "event")
	influxLogQuery := fmt.Sprintf(CreateCheckpointInfluxQueryTemplate,
		cloudcommon.GetInfluxSelectFields(selectors),
		cloudcommon.ClusterInstEvent,
		PrevCheckpoint.Format(time.RFC3339),
		timestamp.Format(time.RFC3339))
	logs, err := services.events.QueryDB(influxLogQuery)
	if err != nil {
		return fmt.Errorf("Unable to query influx: %v", err)
	}

	empty, err := checkInfluxQueryOutput(logs, cloudcommon.ClusterInstEvent)
	skipLogCheck := false
	if err != nil {
		return err
	} else if empty {
		//there are no logs between endTime and the checkpoint, just copy over the checkpoint
		skipLogCheck = true
	}

	seenClusters := make(map[edgeproto.ClusterKey]bool)
	if !skipLogCheck {
		for _, values := range logs[0].Series[0].Values {
			// value should be of the format [timestamp cluster clusterorg cloudlet cloudletorg event]
			if len(values) != len(selectors)+1 {
				return fmt.Errorf("Error parsing influx response")
			}
			key := clusterKeyFromMetricValues(values)
			event := cloudcommon.InstanceEvent(fmt.Sprintf("%v", values[6]))
			// only care about each clusterinsts most recent log
			if _, exists := seenClusters[key]; exists {
				continue
			}
			seenClusters[key] = true
			// if its still up, record it
			if event != cloudcommon.DELETED && event != cloudcommon.UNRESERVED {
				info := edgeproto.ClusterInst{}
				if !s.cache.Get(&key, &info) {
					log.SpanLog(ctx, log.DebugLevelMetrics, "Could not find clusterinst even though event log indicates it is up", "cluster", key)
					continue
				}
				//record the usage up to this point
				err = s.CreateClusterUsageRecord(ctx, &info, timestamp)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to create cluster usage record of checkpointed cluster", "cluster", key, "err", err)
				}
			}
		}
	}

	// check for clusters that got checkpointed but did not have any log events between PrevCheckpoint and this one
	selectors = cloudcommon.ClusterInstEventSelectors
	influxCheckpointQuery := fmt.Sprintf(CreateCheckpointInfluxQueryTemplate,
		cloudcommon.GetInfluxSelectFields(selectors),
		cloudcommon.ClusterInstCheckpoints,
		PrevCheckpoint.Add(-1*time.Minute).Format(time.RFC3339), //small delta to account for conversion rounding inconsistencies
		PrevCheckpoint.Add(time.Minute).Format(time.RFC3339))
	checkpoints, err := services.events.QueryDB(influxCheckpointQuery)
	if err != nil {
		return fmt.Errorf("Unable to query influx: %v", err)
	}

	empty, err = checkInfluxQueryOutput(checkpoints, cloudcommon.ClusterInstCheckpoints)
	if err != nil {
		return err
	} else if empty {
		// no checkpoints made yet, or nothing got checkpointed last time, dont need to do this check
		return nil
	}

	for _, values := range checkpoints[0].Series[0].Values {
		// value should be of the format [timestamp cluster clusterorg cloudlet cloudletorg org status]
		if len(values) != len(selectors)+1 {
			return fmt.Errorf("Error parsing influx response")
		}
		key := clusterKeyFromMetricValues(values)
		// only care about each clusterinsts most recent log
		if _, exists := seenClusters[key]; exists {
			continue
		}
		seenClusters[key] = true
		// record it
		info := edgeproto.ClusterInst{}
		if !s.cache.Get(&key, &info) {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Could not find clusterinst even though event log indicates it is up", "cluster", key)
			continue
		}
		err = s.CreateClusterUsageRecord(ctx, &info, timestamp)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to create cluster usage record of checkpointed cluster", "cluster", key, "err", err)
		}
	}

	return nil
}

// returns all the checkpointed clusterinsts of the most recent checkpoint with regards to timestamp
func GetClusterCheckpoint(ctx context.Context, org string, timestamp time.Time) (*ClusterCheckpoint, error) {
	// wait until the current checkpoint is done if we want to access it, to prevent race conditions with CreateCheckpoint
	for timestamp.After(NextCheckpoint) {
		time.Sleep(time.Second)
	}
	// query from the checkpoint up to the delete
	selectors := append(cloudcommon.ClusterInstEventSelectors, "status", "end")
	influxCheckpointQuery := fmt.Sprintf(GetCheckpointInfluxQueryTemplate,
		cloudcommon.GetInfluxSelectFields(selectors),
		cloudcommon.ClusterInstCheckpoints,
		org,
		timestamp.Format(time.RFC3339))
	checkpoints, err := services.events.QueryDB(influxCheckpointQuery)
	if err != nil {
		return nil, fmt.Errorf("Unable to query influx: %v", err)
	}
	result := ClusterCheckpoint{
		Timestamp: PrevCheckpoint,
		Org:       org,
		Keys:      make([]*edgeproto.ClusterKey, 0),
		Status:    make([]string, 0),
	}

	empty, err := checkInfluxQueryOutput(checkpoints, cloudcommon.ClusterInstCheckpoints)
	if err != nil {
		return nil, err
	} else if empty {
		return &result, nil
	}

	for i, values := range checkpoints[0].Series[0].Values {
		// value should be of the format [measurementTime cluster clusterorg cloudlet cloudletorg status end]
		if len(values) != len(selectors)+1 {
			return nil, fmt.Errorf("Error parsing influx response")
		}
		key := clusterKeyFromMetricValues(values)
		status := fmt.Sprintf("%v", values[6])
		result.Keys = append(result.Keys, &key)
		result.Status = append(result.Status, status)

		measurementTime, err := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[7]))
		if err != nil {
			return nil, fmt.Errorf("unable to parse timestamp of checkpoint")
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
