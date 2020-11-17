package openstack

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

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
	return map[string]*edgeproto.PropertyInfo{}, nil
}

func (o *OpenstackPlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string, stage vmlayer.ProviderInitStage) error {
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
