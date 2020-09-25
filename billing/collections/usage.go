package collections

import (
	"context"
	"fmt"
	"strconv"
	"time"

	client "github.com/influxdata/influxdb/client/v2"
	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/mobiledgex/edge-cloud-infra/billing/zuora"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	opentracing "github.com/opentracing/opentracing-go"
)

var clusterInstUsageInfluxCmd = `select "org","cloudlet","cloudletorg","cluster","clusterorg","flavor","start","end","uptime" from "clusterinst-usage"` +
	`where time >= '%s' and time < '%s'`

var appInstUsageInfluxCmd = `select "app","org","ver","cloudlet","cloudletorg","cluster","clusterorg","flavor","start","end","uptime" from "VMappinst-usage"` +
	`where time >= '%s' and time < '%s'`

var retryMax = 3
var retryPercentage = 0.05 // this number is a percentage, so that the retryDuration is based off of the collectionInterval

func CollectDailyUsage(ctx context.Context) {
	// keep track of how many checkpoints back we need to look when collecting usage, this number should always be at least 1
	// and resets down to 1 on a successful usage collection and increments every time a usage collection failed
	prevSuccessfulCheckpoint := 1
	retryInterval := 5 * time.Minute
	usageInterval, intervalSpecified := ctx.Value("usageInterval").(time.Duration)
	if intervalSpecified {
		retryInterval = time.Duration(retryPercentage * float64(usageInterval))
	}
	for {
		select {
		case <-time.After(timeTilNextCollection(ctx)):
			span := log.StartSpan(log.DebugLevelInfo, "Usage collection thread", opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
			controllers, err := orm.ShowControllerObj(ctx, nil)
			if err != nil {
				retryCount := 0
				for retryCount < retryMax {
					log.SpanLog(ctx, log.DebugLevelInfo, fmt.Sprintf("Unable to get regions to query influx, retrying in %v", retryInterval), "err", err)
					time.Sleep(retryInterval)
					controllers, err = orm.ShowControllerObj(ctx, nil)
					if err == nil {
						break
					}
					retryCount = retryCount + 1
				}
				if err != nil {
					prevSuccessfulCheckpoint = prevSuccessfulCheckpoint + 1
					log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get regions to query influx, waiting until next collection period", "err", err)
					span.Finish()
					continue
				} else {
					prevSuccessfulCheckpoint = 1
				}
			}

			regions := make(map[string]bool)
			for _, controller := range controllers {
				regions[controller.Region] = true
			}
			// get usage from every region
			now := time.Now()
			// grab usage from the previous collection period
			today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
			yesterday := time.Date(now.Year(), now.Month(), now.Day()-(1*prevSuccessfulCheckpoint), 0, 0, 0, 0, time.UTC)
			if intervalSpecified {
				today = now
				yesterday = now.Add(time.Duration(-1*prevSuccessfulCheckpoint) * usageInterval)
			}

			clusterCmd := fmt.Sprintf(clusterInstUsageInfluxCmd, yesterday.Format(time.RFC3339), today.Format(time.RFC3339))
			appCmd := fmt.Sprintf(appInstUsageInfluxCmd, yesterday.Format(time.RFC3339), today.Format(time.RFC3339))
			for region, _ := range regions {
				recordRegionUsage(ctx, region, clusterCmd, appCmd)
			}
			span.Finish()
		}
	}
}

func recordRegionUsage(ctx context.Context, region, clusterCmd, appCmd string) {
	// connect to influx and query it
	influx, err := orm.ConnectInfluxDB(ctx, region)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to connect to influx", "region", region, "err", err)
		return
	}
	defer influx.Close()

	query := influxdb.Query{
		Command:  clusterCmd,
		Database: cloudcommon.EventsDbName,
	}
	resp, err := influx.Query(query)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "InfluxDB query failed",
			"region", region, "query", query, "resp", resp, "err", err)
		return
	}
	if resp.Error() != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "InfluxDB query failed",
			"region", region, "query", query, "err", resp.Error())
		return
	}
	empty, err := checkInfluxQueryOutput(resp.Results, cloudcommon.ClusterInstCheckpoints)
	if empty {
		// no usage records to upload
		return
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Invalid influx output", "region", region, "err", err)
		return
	}
	// record cluster usages
	RecordClusterUsages(ctx, resp)

	// now do it for VM apps
	query.Command = appCmd
	resp, err = influx.Query(query)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "InfluxDB query failed",
			"region", region, "query", query, "resp", resp, "err", err)
		return
	}
	if resp.Error() != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "InfluxDB query failed",
			"region", region, "query", query, "err", resp.Error())
		return
	}
	empty, err = checkInfluxQueryOutput(resp.Results, cloudcommon.AppInstCheckpoints)
	if empty {
		// no usage records to upload
		return
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Invalid influx output", "region", region, "err", err)
		return
	}
	// record cluster usages
	RecordAppUsages(ctx, resp)
}

func RecordClusterUsages(ctx context.Context, resp *client.Response) {
	// call RecordClusterUsage for every entry
	for _, values := range resp.Results[0].Series[0].Values {
		// value should be of the format [timestamp org cloudlet cloudletorg cluster clusterorg flavor start end uptime]
		org := fmt.Sprintf("%v", values[1])
		cloudlet := fmt.Sprintf("%v", values[2])
		cloudletorg := fmt.Sprintf("%v", values[3])
		cluster := fmt.Sprintf("%v", values[4])
		clusterorg := fmt.Sprintf("%v", values[5])
		flavor := fmt.Sprintf("%v", values[6])
		start, _ := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[7]))
		end, _ := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[8]))
		uptime, _ := strconv.ParseFloat(fmt.Sprintf("%v", values[9]), 64)
		key := edgeproto.ClusterInstKey{
			ClusterKey:   edgeproto.ClusterKey{Name: cluster},
			Organization: clusterorg,
			CloudletKey:  edgeproto.CloudletKey{Name: cloudlet, Organization: cloudletorg},
		}
		var accountInfo *zuora.AccountInfo
		accountInfo, err := orm.GetAccountObj(ctx, org)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get account info", "org", org, "err", err)
		} else {
			err = zuora.RecordUsage(accountInfo, key, zuora.UsageTypeCluster, flavor, start, end, uptime)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Unable to record Cluster usage in Zuora", "err", err)
			}
		}
	}
}

func RecordAppUsages(ctx context.Context, resp *client.Response) {
	// call RecordAppUsage for every entry
	for _, values := range resp.Results[0].Series[0].Values {
		// value should be of the format [timestamp app org ver cloudlet cloudletorg cluster clusterorg flavor start end uptime]
		app := fmt.Sprintf("%v", values[1])
		org := fmt.Sprintf("%v", values[2])
		ver := fmt.Sprintf("%v", values[3])
		cloudlet := fmt.Sprintf("%v", values[4])
		cloudletorg := fmt.Sprintf("%v", values[5])
		cluster := fmt.Sprintf("%v", values[6])
		clusterorg := fmt.Sprintf("%v", values[7])
		flavor := fmt.Sprintf("%v", values[8])
		start, _ := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[9]))
		end, _ := time.Parse(time.RFC3339, fmt.Sprintf("%v", values[10]))
		uptime, _ := strconv.ParseFloat(fmt.Sprintf("%v", values[11]), 64)
		key := edgeproto.AppInstKey{
			AppKey: edgeproto.AppKey{
				Organization: org,
				Name:         app,
				Version:      ver,
			},
			ClusterInstKey: edgeproto.ClusterInstKey{
				ClusterKey:   edgeproto.ClusterKey{Name: cluster},
				Organization: clusterorg,
				CloudletKey:  edgeproto.CloudletKey{Name: cloudlet, Organization: cloudletorg},
			},
		}
		var accountInfo *zuora.AccountInfo
		accountInfo, err := orm.GetAccountObj(ctx, org)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get account info", "org", org, "err", err)
		} else {
			err = zuora.RecordUsage(accountInfo, key, zuora.UsageTypeVmApp, flavor, start, end, uptime)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Unable to record App usage in Zuora", "err", err)
			}
		}
	}
}

func timeTilNextCollection(ctx context.Context) time.Duration {
	usageInterval, ok := ctx.Value("usageInterval").(time.Duration)
	if ok {
		return usageInterval
	}
	// default is to collect once a day at the start of the day 12:30am
	now := time.Now().UTC()
	nextDay := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 30, 0, 0, time.UTC)
	return nextDay.Sub(now)
}

func checkInfluxQueryOutput(result []client.Result, dbName string) (bool, error) {
	empty := false
	var valid error
	if len(result) == 0 || len(result[0].Series) == 0 {
		empty = true
	} else if len(result) != 1 ||
		len(result[0].Series) != 1 ||
		len(result[0].Series[0].Values) == 0 ||
		len(result[0].Series[0].Values[0]) == 0 ||
		result[0].Series[0].Name != dbName {
		// should only be 1 series, the 'dbName' one
		valid = fmt.Errorf("Error parsing influx, unexpected format")
	}
	return empty, valid
}
