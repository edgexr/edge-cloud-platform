package main

import (
	"github.com/mobiledgex/edge-cloud-infra/operator-api-gw/defaultoperator"
	"github.com/mobiledgex/edge-cloud-infra/operator-api-gw/gddt"

	"github.com/mobiledgex/edge-cloud/d-match-engine/operator"
	"github.com/mobiledgex/edge-cloud/log"
)

func GetOperatorApiGw(operatorName string) (operator.OperatorApiGw, error) {
	log.DebugLog(log.DebugLevelMexos, "GetOperatorApiGw", "operatorName", operatorName)

	switch operatorName {
	case "gddt":
		fallthrough
	case "GDDT":
		return &gddt.OperatorApiGw{}, nil
	}
	return &defaultoperator.OperatorApiGw{}, nil
}
