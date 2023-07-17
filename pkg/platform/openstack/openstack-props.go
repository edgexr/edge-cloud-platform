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
	"io/ioutil"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/vmlayer"
)

const (
	OS_AUTH_URL             = "OS_AUTH_URL"
	OS_USERNAME             = "OS_USERNAME"
	OS_PASSWORD             = "OS_PASSWORD"
	OS_CACERT_DATA          = "OS_CACERT_DATA"
	OS_CACERT               = "OS_CACERT" // file path on disk
	OS_REGION_NAME          = "OS_REGION_NAME"
	OS_USER_DOMAIN_NAME     = "OS_USER_DOMAIN_NAME"
	OS_IDENTITY_API_VERSION = "OS_IDENTITY_API_VERSION"
	OS_PROJECT_NAME         = "OS_PROJECT_NAME"
	OS_PROJECT_DOMAIN_NAME  = "OS_PROJECT_DOMAIN_NAME"
)

var AccessVarProps = map[string]*edgeproto.PropertyInfo{
	OS_AUTH_URL: {
		Name:        "Openstack auth URL",
		Description: "Openstack auth URL",
		Mandatory:   true,
	},
	OS_USERNAME: {
		Name:        "Openstack user name",
		Description: "Openstack user name",
		Mandatory:   true,
	},
	OS_PASSWORD: {
		Name:        "Openstack user password",
		Description: "Openstack user password",
		Mandatory:   true,
	},
	OS_CACERT_DATA: {
		Name:        "Certificate authority file data",
		Description: "If the Auth URL is using https and the API endpoint's certificate is privately issued, this is the issuing authority's cert that can validate the server's public cert. May be multiple certs in PEM format.",
	},
	OS_PROJECT_NAME: {
		Name:        "Openstack project name",
		Description: "Openstack project name",
	},
	OS_REGION_NAME: {
		Name:        "Openstack region name",
		Description: "Openstack region name",
	},
	OS_USER_DOMAIN_NAME: {
		Name:        "User domain name",
		Description: "User domain name",
		Value:       "default",
	},
	OS_IDENTITY_API_VERSION: {
		Name:        "Openstack server API version",
		Description: "Openstack server API version",
		Value:       "3",
	},
	OS_PROJECT_DOMAIN_NAME: {
		Name:        "Openstack project domain name",
		Description: "Openstack project domain name",
		Value:       "default",
	},
}

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
	if authURL, ok := o.openRCVars[OS_AUTH_URL]; ok {
		if strings.HasPrefix(authURL, "https") {
			if certData, ok := o.openRCVars[OS_CACERT_DATA]; ok {
				key := o.VMProperties.CommonPf.PlatformConfig.CloudletKey
				certFile := vmlayer.GetCertFilePath(key)
				err = ioutil.WriteFile(certFile, []byte(certData), 0644)
				if err != nil {
					return err
				}
				o.openRCVars[OS_CACERT] = certFile
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

func (o *OpenstackPlatform) GetCloudletProjectName() string {
	val, _ := o.openRCVars[OS_PROJECT_NAME]
	return val
}

func (o *OpenstackPlatform) GetConsoleType() string {
	val, _ := o.VMProperties.CommonPf.Properties.GetValue("MEX_CONSOLE_TYPE")
	return val
}
