package vcd

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (v *VcdPlatform) initDebug(nodeMgr *node.NodeMgr, stage vmlayer.ProviderInitStage) {
	if stage == vmlayer.ProviderInitPlatformStartCrm {
		nodeMgr.Debug.AddDebugFunc("dumpVmHrefCache", v.showVmHrefCache)
		nodeMgr.Debug.AddDebugFunc("clearVmHrefCache", v.clearVmHrefCache)
		nodeMgr.Debug.AddDebugFunc("dumpIsoMapTable", v.dumpIsoMapTable)
		nodeMgr.Debug.AddDebugFunc("govcdcmd", v.runVcdCliCommand)
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
func (v *VcdPlatform) runVcdCliCommand(ctx context.Context, req *edgeproto.DebugRequest) string {

	if req.Args == "" {
		return "please specify vcd command in args field"
	}
	rd := csv.NewReader(strings.NewReader(req.Args))
	rd.Comma = ' '
	args, err := rd.Read()
	if err != nil {
		return fmt.Sprintf("failed to split args string, %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "runVcdCliCommand ", "args[0]", args[0], "args[1:]...", args[1:])
	out, err := v.TimedVcdCliCommand(ctx, args[0], args[1:]...)
	if err != nil {
		return fmt.Sprintf("given vcd cmd command failed: %v, %s", err, string(out))
	}
	return string(out)
}

// example usage, login, and show vapp info:
// mcctl --addr https://console-qa.mobiledgex.net:443 debug rundebug  cmd=govcdcmd region=US cloudlet=qa2-cld1 args="/usr/bin/env LC_ALL=C.UTF-8 LANG=C.UTF-8 /home/ubuntu/venv/bin/vcd login $HOST  $ORG $USER -w -i -p $PASSWD"
//  mcctl --addr https://console-qa.mobiledgex.net:443 --output-format=json debug rundebug  cmd=govcdcmd region=US cloudlet=qa2-cld1 args="/usr/bin/env LC_ALL=C.UTF-8 LANG=C.UTF-8 /home/ubuntu/venv/bin/vcd vapp info qa2-cld1-packet-pf-vapp" | jq -r '.[0].output'
func (v *VcdPlatform) TimedVcdCliCommand(ctx context.Context, name string, a ...string) ([]byte, error) {
	parmstr := strings.Join(a, " ")
	start := time.Now()

	log.SpanLog(ctx, log.DebugLevelInfra, "govcdcmd Command Start", "name", name, "parms", parmstr)
	newSh := infracommon.Sh(v.vcdVars)

	out, err := newSh.Command(name, a).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "govcdcmd command returned error", "parms", parmstr, "out", string(out), "err", err, "elapsed time", time.Since(start))
		return out, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "govcdcmd Command Done", "parmstr", parmstr, "elapsed time", time.Since(start))
	return out, nil
}
