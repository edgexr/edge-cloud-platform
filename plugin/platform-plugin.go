package main

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/azure"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/gcp"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/mexdind"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/openstack"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
)

func GetPlatform(plat string) (platform.Platform, error) {
	switch plat {
	case "PLATFORM_TYPE_OPENSTACK":
		return &openstack.Platform{}, nil
	case "PLATFORM_TYPE_AZURE":
		return &azure.Platform{}, nil
	case "PLATFORM_TYPE_GCP":
		return &gcp.Platform{}, nil
	case "PLATFORM_TYPE_MEXDIND":
		return &mexdind.Platform{}, nil
	}
	return nil, fmt.Errorf("unknown platform %s", plat)
}

func main() {}
