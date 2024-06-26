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

package platform

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	operator "github.com/edgexr/edge-cloud-platform/pkg/nrem-platform"
	"github.com/edgexr/edge-cloud-platform/pkg/nrem-platform/defaultoperator"
	"github.com/edgexr/edge-cloud-platform/pkg/nrem-platform/operalpha"
)

func GetOperatorApiGw(ctx context.Context, operatorName string) (operator.OperatorApiGw, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetOperatorApiGw", "operatorName", operatorName)

	var outApiGw operator.OperatorApiGw
	switch operatorName {
	case "gddt":
		fallthrough
	case "GDDT":
		outApiGw = &operalpha.OperatorApiGw{}
	default:
		outApiGw = &defaultoperator.OperatorApiGw{}
	}
	return outApiGw, nil
}
