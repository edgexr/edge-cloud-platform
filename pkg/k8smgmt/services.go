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

package k8smgmt

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

type svcItems struct {
	Items []v1.Service `json:"items"`
}

func GetServices(ctx context.Context, client ssh.Client, names *KubeNames, ops ...GetObjectsOp) ([]v1.Service, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get services", "kconf", names.KconfName)
	if names.DeploymentType == cloudcommon.DeploymentTypeDocker {
		// just populate the service names
		svcs := svcItems{}
		for _, sn := range names.ServiceNames {
			item := v1.Service{}
			item.Name = sn
			svcs.Items = append(svcs.Items, item)
		}
		return svcs.Items, nil
	}
	return GetKubeServices(ctx, client, names.GetKConfNames(), ops...)
}

func GetKubeServices(ctx context.Context, client ssh.Client, names *KConfNames, ops ...GetObjectsOp) ([]v1.Service, error) {
	svcs := svcItems{}
	err := GetObjects(ctx, client, names, "svc", &svcs, ops...)
	if err != nil {
		return nil, err
	}
	return svcs.Items, nil
}
