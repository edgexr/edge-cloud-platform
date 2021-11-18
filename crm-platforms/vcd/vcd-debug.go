package vcd

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (v *VcdPlatform) initDebug(nodeMgr *node.NodeMgr, stage vmlayer.ProviderInitStage) {
	if stage == vmlayer.ProviderInitPlatformStartCrm {
		nodeMgr.Debug.AddDebugFunc("dumpVmHrefCache", v.showVmHrefCache)
		nodeMgr.Debug.AddDebugFunc("clearVmHrefCache", v.clearVmHrefCache)
		nodeMgr.Debug.AddDebugFunc("dumpIsoMapTable", v.dumpIsoMapTable)
	} else if stage == vmlayer.ProviderInitPlatformStartShepherd {
		// shepherd uses the vm href cache but not the iso map
		nodeMgr.Debug.AddDebugFunc("dumpVmHrefCache", v.showVmHrefCache)
		nodeMgr.Debug.AddDebugFunc("clearVmHrefCache", v.clearVmHrefCache)
	}

}

func (v *VcdPlatform) showVmHrefCache(ctx context.Context, req *edgeproto.DebugRequest) string {
	return v.DumpVmHrefCache(ctx)
}

func (v *VcdPlatform) clearVmHrefCache(ctx context.Context, req *edgeproto.DebugRequest) string {
	v.ClearVmHrefCache(ctx)
	return "VM HREF cache cleared"
}

func (v *VcdPlatform) dumpIsoMapTable(ctx context.Context, req *edgeproto.DebugRequest) string {
	out, err := v.updateIsoNamesMap(ctx, IsoMapActionDump, "", "")
	if err != nil {
		return err.Error()
	}
	return out
}
