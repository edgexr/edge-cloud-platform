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
	"context"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

var retryMax = 3
var retryPercentage = 0.05 // this number is a percentage, so that the retryInterval is based off of the collectionInterval

func CollectBillingUsage(collectInterval time.Duration) {
	retryInterval := 5 * time.Minute
	nextCollectTime := getNextCollectTime(time.Now(), collectInterval)
	prevCollectTime := nextCollectTime.Add(collectInterval * (-1))
	if collectInterval.Seconds() > float64(0) {
		retryInterval = time.Duration(retryPercentage * float64(collectInterval))
	}
	for {
		select {
		case <-time.After(nextCollectTime.Sub(time.Now())):
			span := log.StartSpan(log.DebugLevelInfo, "Billing usage collection thread")
			ctx := log.ContextWithSpan(context.Background(), span)
			if !billingEnabled(ctx) {
				prevCollectTime = nextCollectTime
				nextCollectTime = getNextCollectTime(nextCollectTime, collectInterval)
				continue
			}
			controllers, err := ShowControllerObj(ctx, NoUserClaims, NoShowFilter)
			if err != nil {
				retryCount := 0
				for retryCount < retryMax {
					log.SpanLog(ctx, log.DebugLevelInfo, fmt.Sprintf("Unable to get regions to query influx, retrying in %v", retryInterval), "err", err)
					time.Sleep(retryInterval)
					controllers, err = ShowControllerObj(ctx, NoUserClaims, NoShowFilter)
					if err == nil {
						break
					}
					retryCount = retryCount + 1
				}
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get regions to query influx, waiting until next collection period", "err", err)
					nextCollectTime = getNextCollectTime(nextCollectTime, collectInterval)
					span.Finish()
					continue
				}
			}

			regions := make(map[string]bool)
			for _, controller := range controllers {
				regions[controller.Region] = true
			}
			// get usage from every region
			for region, _ := range regions {
				recordRegionUsage(ctx, region, prevCollectTime, nextCollectTime)
			}
			prevCollectTime = nextCollectTime
			nextCollectTime = getNextCollectTime(nextCollectTime, collectInterval)
			span.Finish()
		}
	}
}

func recordRegionUsage(ctx context.Context, region string, start, end time.Time) {
	poolMap := make(map[string]string)
	err := ctrlclient.ShowCloudletPoolStream(ctx, &ormutil.RegionContext{SkipAuthz: true, Region: region, Database: database}, &edgeproto.CloudletPool{}, connCache, nil, func(pool *edgeproto.CloudletPool) error {
		for _, clKey := range pool.Cloudlets {
			poolMap[clKey.Name] = pool.Key.Organization
		}
		return nil
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get cloudletpool list", "region", region, "err", err)
		return
	}
	rc := InfluxDBContext{region: region}
	appIn := ormapi.RegionAppInstUsage{
		Region:    region,
		StartTime: start,
		EndTime:   end,
		VmOnly:    true,
	}
	eventCmd := AppInstUsageEventsQuery(&appIn, []string{})
	checkpointCmd := AppInstCheckpointsQuery(&appIn, []string{})
	eventResp, checkResp, err := GetEventAndCheckpoint(ctx, &rc, eventCmd, checkpointCmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Error gathering app usage for billing", "region", region, "err", err)
		return
	}
	appUsage, err := GetAppUsage(eventResp, checkResp, appIn.StartTime, appIn.EndTime, appIn.Region)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Error parsing app usage for billing", "region", region, "err", err)
		return
	}
	recordAppUsages(ctx, appUsage, poolMap, region)

	clusterIn := ormapi.RegionClusterInstUsage{
		Region:    region,
		StartTime: start,
		EndTime:   end,
	}
	eventCmd = ClusterUsageEventsQuery(&clusterIn, []string{})
	checkpointCmd = ClusterCheckpointsQuery(&clusterIn, []string{})
	eventResp, checkResp, err = GetEventAndCheckpoint(ctx, &rc, eventCmd, checkpointCmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Error gathering cluster usage for billing", "region", region, "err", err)
		return
	}
	clusterUsage, err := GetClusterUsage(ctx, eventResp, checkResp, clusterIn.StartTime, clusterIn.EndTime, clusterIn.Region)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Error parsing cluster usage for billing", "region", region, "err", err)
		return
	}
	recordClusterUsages(ctx, clusterUsage, poolMap, region)
}

func recordAppUsages(ctx context.Context, usage *ormapi.MetricData, cloudletPoolMap map[string]string, region string) {
	orgTracker := make(map[string][]billing.UsageRecord)
	if len(usage.Series) == 0 {
		// techincally if GetAppUsage doesnt fail, this should be impossible, but check anyway so we dont crash if it did happen
		log.SpanLog(ctx, log.DebugLevelInfo, "Invalid app usage")
		return
	}
	for _, value := range usage.Series[0].Values {
		// ordering is from appInstDataColumns
		newAppInst := edgeproto.AppInstKey{
			AppKey: edgeproto.AppKey{
				Name:         fmt.Sprintf("%v", value[1]),
				Organization: fmt.Sprintf("%v", value[2]),
				Version:      fmt.Sprintf("%v", value[3]),
			},
			ClusterInstKey: edgeproto.VirtualClusterInstKey{
				Organization: fmt.Sprintf("%v", value[5]),
				ClusterKey:   edgeproto.ClusterKey{Name: fmt.Sprintf("%v", value[4])},
				CloudletKey: edgeproto.CloudletKey{
					Name:         fmt.Sprintf("%v", value[6]),
					Organization: fmt.Sprintf("%v", value[7]),
				},
			},
		}
		checkOrg := cloudletPoolMap[newAppInst.ClusterInstKey.CloudletKey.Name]
		if checkOrg == newAppInst.ClusterInstKey.CloudletKey.Organization {
			continue // ignore non public cloudlets
		}
		startTime, ok := value[10].(time.Time)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to parse time", "starttime", value[10])
			continue
		}
		endTime, ok := value[11].(time.Time)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to parse time", "endtime", value[11])
			continue
		}
		newRecord := billing.UsageRecord{
			FlavorName: fmt.Sprintf("%v", value[8]),
			NodeCount:  1,
			AppInst:    &newAppInst,
			StartTime:  startTime,
			EndTime:    endTime,
			Region:     region,
		}
		records, _ := orgTracker[newAppInst.AppKey.Organization]
		orgTracker[newAppInst.AppKey.Organization] = append(records, newRecord)
	}
	for org, record := range orgTracker {
		var accountInfo *ormapi.AccountInfo
		accountInfo, err := GetAccountObj(ctx, org)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get account info", "org", org, "err", err)
			continue
		} else {
			err = serverConfig.BillingService.RecordUsage(ctx, region, accountInfo, record)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Unable to record app usage", "err", err)
			}
		}
	}
}

func recordClusterUsages(ctx context.Context, usage *ormapi.MetricData, cloudletPoolMap map[string]string, region string) {
	orgTracker := make(map[string][]billing.UsageRecord)
	if len(usage.Series) == 0 {
		// techincally if GetClusterUsage doesnt fail, this should be impossible, but check anyway so we dont crash if it did happen
		log.SpanLog(ctx, log.DebugLevelInfo, "Invalid cluster usage")
		return
	}
	for _, value := range usage.Series[0].Values {
		if len(value) != 12 {
			log.SpanLog(ctx, log.DebugLevelInfo, "Invalid cluster record", "record", value)
		}
		// ordering is from clusterInstDataColumns
		newClusterInst := edgeproto.ClusterInstKey{
			Organization: fmt.Sprintf("%v", value[2]),
			ClusterKey:   edgeproto.ClusterKey{Name: fmt.Sprintf("%v", value[1])},
			CloudletKey: edgeproto.CloudletKey{
				Name:         fmt.Sprintf("%v", value[3]),
				Organization: fmt.Sprintf("%v", value[4]),
			},
		}
		checkOrg := cloudletPoolMap[newClusterInst.CloudletKey.Name]
		if checkOrg == newClusterInst.CloudletKey.Organization {
			continue // ignore non public cloudlets
		}
		startTime, ok := value[8].(time.Time)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to parse time", "starttime", value[8])
			continue
		}
		endTime, ok := value[9].(time.Time)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to parse time", "endtime", value[9])
			continue
		}
		nodeCount, ok := value[6].(int64)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to parse nodecount", "nodecount", value[6])
			continue
		}
		newRecord := billing.UsageRecord{
			FlavorName:  fmt.Sprintf("%v", value[5]),
			NodeCount:   int(nodeCount),
			ClusterInst: &newClusterInst,
			StartTime:   startTime,
			EndTime:     endTime,
			IpAccess:    fmt.Sprintf("%v", value[7]),
			Region:      region,
		}
		records, _ := orgTracker[newClusterInst.Organization]
		orgTracker[newClusterInst.Organization] = append(records, newRecord)
	}
	for org, record := range orgTracker {
		var accountInfo *ormapi.AccountInfo
		accountInfo, err := GetAccountObj(ctx, org)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get account info", "org", org, "err", err)
			continue
		} else {
			err = serverConfig.BillingService.RecordUsage(ctx, region, accountInfo, record)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Unable to record cluster usage", "err", err)
			}
		}
	}
}

func getNextCollectTime(now time.Time, collectInterval time.Duration) time.Time {
	if collectInterval.Seconds() > float64(0) { // if positive, use it
		return now.Truncate(collectInterval).Add(collectInterval) // truncate it so the times are nice
	}
	// if the collection interval specified is less than 0, the default is to collect once a day
	// default is to collect once a day at the start of the day 12am
	nextDay := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	return nextDay
}
