package main

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/operator-api-gw/gddt"
	"github.com/mobiledgex/edge-cloud/d-match-engine/operator"
	"github.com/mobiledgex/edge-cloud/d-match-engine/operator/defaultoperator"
	"github.com/mobiledgex/edge-cloud/log"
)

func GetOperatorApiGw(ctx context.Context, operatorName string) (operator.OperatorApiGw, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetOperatorApiGw", "operatorName", operatorName)

	var outApiGw operator.OperatorApiGw
	switch operatorName {
	case "gddt":
		fallthrough
	case "GDDT":
		outApiGw = &gddt.OperatorApiGw{}
	default:
		outApiGw = &defaultoperator.OperatorApiGw{}
	}
	return outApiGw, nil
}
