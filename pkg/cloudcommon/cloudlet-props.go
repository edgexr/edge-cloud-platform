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

package cloudcommon

import (
	"fmt"
	"strconv"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

const (
	IngressHTTPPort          = "INGRESS_HTTP_PORT"
	IngressHTTPSPort         = "INGRESS_HTTPS_PORT"
	IngressControllerPresent = "INGRESS_CONTROLLER_PRESENT"
	WorkloadManager          = "WORKLOAD_MANAGER"
)

var IngressHTTPPortProp = &edgeproto.PropertyInfo{
	Name:        "Ingress HTTP Port",
	Description: "Port number to override the default port 80 for HTTP ports using ingress objects in Kubernetes clusters, typically used when a NAT fronts the ingress",
}

var IngressHTTPSPortProp = &edgeproto.PropertyInfo{
	Name:        "Ingress HTTPS Port",
	Description: "Port number to override the default port 443 for HTTPS ports with TLS using ingress objects in Kubernetes clusters, typically used when a NAT fronts the ingress",
}

var IngressControllerPresentProp = &edgeproto.PropertyInfo{
	Name:        "Ingress Controller is Present",
	Description: "Pre-existing clusters or clusters deployed by cluster manager come with the ingress controller already installed",
}

var WorkloadManagerProp = &edgeproto.PropertyInfo{
	Name:        "Specify the workload manager",
	Description: "Set to \"osm\" to use OSM as the workload manager, otherwise defaults to the Edge Cloud k8s workload manager.",
}

func ValidateProps(vars map[string]string) error {
	if _, err := GetIngressHTTPPort(vars); err != nil {
		return err
	}
	if _, err := GetIngressHTTPSPort(vars); err != nil {
		return err
	}
	return nil
}

func GetIngressHTTPPort(vars map[string]string) (int32, error) {
	if val, ok := vars[IngressHTTPPort]; ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("invalid Ingress HTTP port value %s, %s", val, err)
		}
		if v <= 0 || v > 65535 {
			return 0, fmt.Errorf("ingress HTTP port value %d out of range", v)
		}
		return int32(v), nil
	}
	return 80, nil
}

func GetIngressHTTPSPort(vars map[string]string) (int32, error) {
	if val, ok := vars[IngressHTTPSPort]; ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("invalid Ingress HTTPS port value %s, %s", val, err)
		}
		if v <= 0 || v > 65535 {
			return 0, fmt.Errorf("ingress HTTPS port value %d out of range", v)
		}
		return int32(v), nil
	}
	return 443, nil
}
