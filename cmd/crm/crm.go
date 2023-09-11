package main

import (
	"github.com/edgexr/edge-cloud-platform/pkg/crm"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/platforms"
)

func main() {
	crm.Run(platforms.All.GetBuilders())
}
