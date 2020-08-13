package zuora

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

var referenceTime = "2006-01-02T15:04:05"

var UsageTypeCluster = "cluster"
var UsageTypeVmApp = "VmApp"

func RecordUsage(account *AccountInfo, key interface{}, usageType, flavorName string, startTime, endTime time.Time, runTime float64) error {
	var chargeId, desc string
	if usageType == UsageTypeCluster {
		clusterInstKey := key.(edgeproto.ClusterInstKey)
		chargeId = getProductRatePlanChargeId(&clusterInstKey, flavorName)
		desc = fmt.Sprintf("Org: %s, Clusterinst: %s, Cloudlet: %s, Flavor: %s",
			clusterInstKey.Organization, clusterInstKey.ClusterKey.Name, clusterInstKey.CloudletKey.Name, flavorName)
	} else if usageType == UsageTypeVmApp {
		appInstKey := key.(edgeproto.AppInstKey)
		// TODO: right now getProductRatePlan returns a static chargeID, accomodate it for App flavors when that part gets fleshed out
		chargeId = getProductRatePlanChargeId(nil, flavorName)
		desc = fmt.Sprintf("App: %s, Org: %s, Version: %s, Cloudlet: %s, Flavor: %s",
			appInstKey.AppKey.Name, appInstKey.AppKey.Organization, appInstKey.AppKey.Version, appInstKey.ClusterInstKey.CloudletKey.Name, flavorName)
	}
	chargeNumber, err := getSubChargeNumber(account.AccountNumber, chargeId)
	if err != nil {
		return fmt.Errorf("unable to get charge number: %v", err)
	}
	newUsage := CreateUsage{
		AccountNumber:      account.AccountNumber,
		SubscriptionNumber: account.SubscriptionNumber,
		ChargeNumber:       chargeNumber,
		Quantity:           runTime / 60, // assume we port right from influx and runTime is in seconds still
		StartDateTime:      startTime.Format(referenceTime),
		EndDateTime:        endTime.Format(referenceTime),
		UOM:                "Minute",
		Description:        desc,
	}

	resp, err := newZuoraReq("POST", ZuoraUrl+UsageEndpoint, newUsage)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	usageResp := GenericResp{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&usageResp)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !usageResp.Success {
		return fmt.Errorf("Error creating usage record")
	}
	return nil
}

// for some reason zuora needs to have the charge id generated with the subscription, not the actual original charge id of the rateplancharge
func getSubChargeNumber(accountNum, ratePlanChargeId string) (string, error) {
	subInfo, err := getSubscription(accountNum)
	if err != nil {
		return "", err
	}
	for _, ratePlan := range subInfo.Subscriptions[0].RatePlans {
		for _, ratePlanCharges := range ratePlan.RatePlanCharges {
			if ratePlanChargeId == ratePlanCharges.ProductRatePlanChargeID {
				return ratePlanCharges.Number, nil
			}
		}
	}
	return "", fmt.Errorf("Rate plan charge does not exist in the subscription")
}
