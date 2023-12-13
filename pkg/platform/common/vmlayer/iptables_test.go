package vmlayer

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func testInitVMPlatform(ctx context.Context, v *VMPlatform) error {
	props := make(map[string]*edgeproto.PropertyInfo)
	for k, v := range VMProviderProps {
		props[k] = v
	}
	platformConfig := &platform.PlatformConfig{}
	err := v.VMProperties.CommonPf.InitInfraCommon(ctx, platformConfig, props)
	if err != nil {
		return err
	}
	return nil
}

func TestSetupIptablesRulesForRootLB(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	infracommon.SetTestMode(true)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	vp := VMPlatform{}
	err := testInitVMPlatform(ctx, &vp)
	require.Nil(t, err)

	client := &pc.TestClient{}
	sshCidrsAllowed := []string{infracommon.RemoteCidrAll, infracommon.RemoteCidrAllIPV6}
	egressRestricted := false
	secGrpName := "sec-group"
	rules := []edgeproto.SecurityRule{}
	commonSharedAccess := true // used by VCD
	enableIPV6 := true
	err = vp.VMProperties.SetupIptablesRulesForRootLB(ctx, client, sshCidrsAllowed, egressRestricted, secGrpName, rules, commonSharedAccess, enableIPV6)
	require.Nil(t, err)

	checkTestClientCmds(t, client, "TestSetupIptablesRulesForRootLB")
}

func TestSetupForwardingIptables(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	infracommon.SetTestMode(true)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	vp := VMPlatform{}
	err := testInitVMPlatform(ctx, &vp)
	require.Nil(t, err)

	client := &pc.TestClient{}
	externalIfname := "ens3"
	internalIfname := "ens4"
	action := infracommon.InterfaceActionsOp{
		CreateIptables: true,
	}
	err = vp.setupForwardingIptables(ctx, client, externalIfname, internalIfname, &action, infracommon.IPV4)
	require.Nil(t, err)
	err = vp.setupForwardingIptables(ctx, client, externalIfname, internalIfname, &action, infracommon.IPV6)
	require.Nil(t, err)

	checkTestClientCmds(t, client, "TestSetupForwardingIptables")
}

func checkTestClientCmds(t *testing.T, client *pc.TestClient, testName string) {
	buf := bytes.Buffer{}

	ns := "iptablestestns"
	buf.WriteString("#!/bin/bash\n")
	buf.WriteString("set -e\n")
	buf.WriteString("ip netns add " + ns + "\n")

	// This generates a script that can be run to test if the rules
	// syntax is valid. The script creates a new network namespace to run
	// the rules, then deletes it afterwards, so it avoids touching the
	// machine's real ip tables. We also compare it to an expected file
	// to validate any changes to syntax/rules.
	for _, cmd := range client.Cmds {
		cmd = strings.TrimPrefix(cmd, "sudo ")
		if strings.HasPrefix(cmd, "iptables") || strings.HasPrefix(cmd, "ip6tables") {
			buf.WriteString("ip netns exec " + ns + " " + cmd + "\n")
		} else {
			buf.WriteString("# " + cmd + "\n")
		}
	}
	buf.WriteString("ip netns delete " + ns + "\n")

	testutil.CompareExpectedFileData(t, testName, "sh", buf.String())
}
