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
	case "openstack":
		return &openstack.Platform{}, nil
	case "azure":
		return &azure.Platform{}, nil
	case "gcp":
		return &gcp.Platform{}, nil
	case "mexdind":
		return &mexdind.Platform{}, nil
	}
	return nil, fmt.Errorf("unknown platform %s", plat)
}

func main() {}
