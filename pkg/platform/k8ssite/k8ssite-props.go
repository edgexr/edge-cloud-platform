// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8ssite

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
)

const (
	KUBECONFIG = "KUBECONFIG"
)

var AccessVarProps = map[string]*edgeproto.PropertyInfo{
	KUBECONFIG: {
		Name:        "Kubernetes cluster config file data",
		Description: "Contents of Kubernetes cluster config file used with kubectl to access the cluster, must have admin permissions for the cluster",
		Mandatory:   true,
	},
}

var Props = map[string]*edgeproto.PropertyInfo{
	infracommon.ExternalIPMap:            infracommon.ExternalIPMapProp,
	cloudcommon.IngressHTTPPort:          cloudcommon.IngressHTTPPortProp,
	cloudcommon.IngressHTTPSPort:         cloudcommon.IngressHTTPSPortProp,
	cloudcommon.IngressControllerPresent: cloudcommon.IngressControllerPresentProp,
}

func (s *K8sSite) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	accessVars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	s.accessVars = accessVars
	return nil
}
