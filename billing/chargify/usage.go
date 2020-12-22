package chargify

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (bs *BillingService) RecordUsage(ctx context.Context, account *billing.AccountInfo, usageRecords []billing.UsageRecord) error {
	for _, record := range usageRecords {
		var memo string
		var cloudlet *edgeproto.CloudletKey
		if record.AppInst == nil && record.ClusterInst == nil {
			return fmt.Errorf("invalid usage record, either appinstkey or clusterinstkey must be specified")
		} else if record.AppInst == nil {
			cloudlet = &record.ClusterInst.CloudletKey
			memo = fmt.Sprintf("{%s}, Flavor: %s, NumNodes %d, start: %s, end %s", record.ClusterInst.String(), record.FlavorName, record.NodeCount, record.StartTime.UTC().Format(time.RFC3339), record.EndTime.UTC().Format(time.RFC3339))
		} else { //record.ClusterInst == nil
			cloudlet = &record.AppInst.ClusterInstKey.CloudletKey
			memo = fmt.Sprintf("{%s}, Flavor: %s, start: %s, end %s", record.AppInst.String(), record.FlavorName, record.StartTime.UTC().Format(time.RFC3339), record.EndTime.UTC().Format(time.RFC3339))
		}
		componentId := getComponentCode(record.FlavorName, cloudlet, record.StartTime, record.EndTime)
		endpoint := "/subscriptions/" + account.SubscriptionId + "/components/" + componentId + "/usages.json"

		duration := int(record.EndTime.Sub(record.StartTime).Minutes() * float64(record.NodeCount))
		newUsage := Usage{
			Quantity: duration,
			Memo:     memo,
		}
		resp, err := newChargifyReq("POST", endpoint, UsageWrapper{Usage: &newUsage})
		if err != nil {
			return fmt.Errorf("Error sending request: %v\n", err)
		}
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			return infracommon.GetReqErr(resp.Body)
		}
	}
	return nil
}
