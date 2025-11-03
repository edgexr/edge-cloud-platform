// Copyright 2025 EdgeXR, Inc
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

package metal3

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/metal3-io/baremetal-operator/apis/metal3.io/v1alpha1"
)

func GetBareMetalHosts(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, namespace string) ([]v1alpha1.BareMetalHost, error) {
	cmd := fmt.Sprintf("kubectl %s get baremetalhosts -n %s -o json", names.KconfArg, namespace)
	log.SpanLog(ctx, log.DebugLevelInfra, "get baremetalhosts", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("get baremetalhosts failed, %s, %v", out, err)
	}
	blist := v1alpha1.BareMetalHostList{}
	err = json.Unmarshal([]byte(out), &blist)
	if err != nil {
		return nil, fmt.Errorf("unmarshal baremetalhosts failed, %s, %v", out, err)
	}
	return blist.Items, nil
}
