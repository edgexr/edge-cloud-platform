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

package chargify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/edgeproto"
)

var dedicatedLB = "dedicatedLB"

func (bs *BillingService) RecordUsage(ctx context.Context, region string, account *ormapi.AccountInfo, usageRecords []billing.UsageRecord) error {
	for _, record := range usageRecords {
		var memo string
		var cloudlet *edgeproto.CloudletKey
		// chargify memo does not like '<' and '>' chars, so replace them with brackets
		replacer := strings.NewReplacer(
			"<", "{",
			">", "}")
		if record.AppInst == nil && record.ClusterInst == nil {
			return fmt.Errorf("invalid usage record, either appinstkey or clusterinstkey must be specified")
		} else if record.AppInst == nil {
			cloudlet = &record.ClusterInst.CloudletKey
			clusterStr := replacer.Replace(record.ClusterInst.String())
			memo = fmt.Sprintf("{%s}, Flavor: %s, NumNodes %d, start: %s, end %s", clusterStr, record.FlavorName, record.NodeCount, record.StartTime.UTC().Format(time.RFC3339), record.EndTime.UTC().Format(time.RFC3339))
		} else { //record.ClusterInst == nil
			cloudlet = &record.AppInst.ClusterInstKey.CloudletKey
			appStr := replacer.Replace(record.AppInst.String())
			memo = fmt.Sprintf("{%s}, Flavor: %s, start: %s, end %s", appStr, record.FlavorName, record.StartTime.UTC().Format(time.RFC3339), record.EndTime.UTC().Format(time.RFC3339))
		}
		// in docker, nodeCount isn't used, but we can't have multiplication by 0, and we dont want to show a nodecount of 0 in the memo either
		if record.NodeCount == 0 {
			record.NodeCount = 1
		}
		componentId := getComponentCode(record.FlavorName, region, cloudlet, record.StartTime, record.EndTime)
		endpoint := "/subscriptions/" + account.SubscriptionId + "/components/" + componentId + "/usages.json"

		singleNodeDuration := int(record.EndTime.Sub(record.StartTime).Minutes())
		newUsage := Usage{
			Quantity: singleNodeDuration * record.NodeCount,
			Memo:     memo,
		}
		resp, err := newChargifyReq("POST", endpoint, UsageWrapper{Usage: &newUsage})
		if err != nil {
			return fmt.Errorf("Error sending request: %v\n", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return infracommon.GetReqErr(resp.Body)
		}
		if record.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED.String() {
			lbUsage := Usage{
				Quantity: singleNodeDuration,
				Memo:     memo,
			}
			componentId = getComponentCode(dedicatedLB, region, cloudlet, record.StartTime, record.EndTime)
			endpoint = "/subscriptions/" + account.SubscriptionId + "/components/" + componentId + "/usages.json"
			lbResp, err := newChargifyReq("POST", endpoint, UsageWrapper{Usage: &lbUsage})
			if err != nil {
				return fmt.Errorf("Error sending request: %v\n", err)
			}
			defer lbResp.Body.Close()
			if lbResp.StatusCode != http.StatusOK {
				return infracommon.GetReqErr(lbResp.Body)
			}
		}
	}
	return nil
}
