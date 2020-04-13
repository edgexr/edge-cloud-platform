package openstack

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (s *Platform) initDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc("oscmd", s.runOsCmd)
}

func (s *Platform) runOsCmd(ctx context.Context, req *edgeproto.DebugRequest) string {
	if req.Args == "" {
		return "please specify openstack command in args field"
	}
	rd := csv.NewReader(strings.NewReader(req.Args))
	rd.Comma = ' '
	args, err := rd.Read()
	if err != nil {
		return fmt.Sprintf("failed to split args string, %v", err)
	}
	out, err := s.TimedOpenStackCommand(ctx, args[0], args[1:]...)
	if err != nil {
		return fmt.Sprintf("openstack command failed: %v, %s", err, string(out))
	}
	return string(out)
}
