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

package openstack

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
)

var OpenstackProps = map[string]*edgeproto.PropertyInfo{
	"MEX_CONSOLE_TYPE": {
		Name:        "Openstack console type",
		Description: "Openstack supported console type: novnc, xvpvnc, spice, rdp, serial, mks",
		Value:       "novnc",
	},
}

func (o *OpenstackPlatform) GetOpenRCVars(ctx context.Context, accessApi platform.AccessApi) error {
	vars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	o.openRCVars = vars
	if authURL, ok := o.openRCVars["OS_AUTH_URL"]; ok {
		if strings.HasPrefix(authURL, "https") {
			if certData, ok := o.openRCVars["OS_CACERT_DATA"]; ok {
				key := o.VMProperties.CommonPf.PlatformConfig.CloudletKey
				certFile := vmlayer.GetCertFilePath(key)
				err = ioutil.WriteFile(certFile, []byte(certData), 0644)
				if err != nil {
					return err
				}
				o.openRCVars["OS_CACERT"] = certFile
			}
		}
	}
	return nil
}

func (o *OpenstackPlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return OpenstackProps, nil
}

func (o *OpenstackPlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	err := o.GetOpenRCVars(ctx, accessApi)
	if err != nil {
		return err
	}
	return nil
}

func (o *OpenstackPlatform) GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, physicalName string) string {
	return fmt.Sprintf("/secret/data/%s/cloudlet/openstack/%s/%s/openrc.json", region, key.Organization, physicalName)
}

func (o *OpenstackPlatform) GetCloudletProjectName() string {
	val, _ := o.openRCVars["OS_PROJECT_NAME"]
	return val
}

func (o *OpenstackPlatform) GetConsoleType() string {
	val, _ := o.VMProperties.CommonPf.Properties.GetValue("MEX_CONSOLE_TYPE")
	return val
}
