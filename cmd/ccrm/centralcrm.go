package main

import (
	"github.com/edgexr/edge-cloud-platform/pkg/ccrm"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/platforms"
)

func main() {
	c := ccrm.NewCCRM(node.NodeTypeCCRM, platforms.All.GetBuilders())
	c.Run()
}
