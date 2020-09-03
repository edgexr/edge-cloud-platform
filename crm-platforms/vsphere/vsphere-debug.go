package vsphere

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (v *VSpherePlatform) initDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc("govccmd", v.runGovcCommand)
}

func (o *VSpherePlatform) runGovcCommand(ctx context.Context, req *edgeproto.DebugRequest) string {
	if req.Args == "" {
		return "please specify govc command in args field"
	}
	rd := csv.NewReader(strings.NewReader(req.Args))
	rd.Comma = ' '
	args, err := rd.Read()
	if err != nil {
		return fmt.Sprintf("failed to split args string, %v", err)
	}
	out, err := o.TimedGovcCommand(ctx, args[0], args[1:]...)
	if err != nil {
		return fmt.Sprintf("govc command failed: %v, %s", err, string(out))
	}
	return string(out)
}
