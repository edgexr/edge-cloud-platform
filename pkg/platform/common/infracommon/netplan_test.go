package infracommon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestNetplanFile(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	SetTestMode(true)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	client := &pc.TestClient{}
	client.OutputResponder = func(cmd string) (string, error) {
		// Translate queries and writes to /etc/netplan to current dir test files
		if cmd == "ls -1 /etc/netplan/*.yaml" {
			// ls in local dir
			out, err := exec.Command("/bin/bash", "-c", "ls -1 test-netplan*.yaml | grep -v expected.yaml").CombinedOutput()
			return string(out), err
		} else if strings.HasPrefix(cmd, "cat ") {
			out, err := exec.Command("/bin/bash", "-c", cmd).CombinedOutput()
			return string(out), err
		} else if strings.HasPrefix(cmd, "sudo bash -c 'base64 -d") {
			// pc.WriteFile
			cmd = strings.TrimPrefix(cmd, "sudo ")
			cmd = strings.ReplaceAll(cmd, "/etc/netplan/", "")
			out, err := exec.Command("/bin/bash", "-c", cmd).CombinedOutput()
			return string(out), err
		} else if strings.HasPrefix(cmd, "sudo netplan apply") {
			return "", nil
		}
		return "", fmt.Errorf("unsupported command %s", cmd)
	}

	config2FileRoot := "test-netplan-config2"
	config2File := config2FileRoot + ".yaml"
	os.Remove(config2File)

	// read network config from test file
	config, err := GetNetworkConfig(ctx, client)
	require.Nil(t, err)
	require.Equal(t, 1, len(config.NetplanFiles))
	require.Equal(t, 1, len(config.ethLookup))

	// check that parser read file correctly
	eth := config.GetInterface("ens3", "test-netplan-config")
	require.NotNil(t, eth)
	require.Equal(t, []string{"10.101.0.2/16", "fc00:101:ecec::2/64"}, eth.Addresses)
	require.Equal(t, []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"}, eth.Nameservers.Addresses)
	routes := []*NetplanRoute{{
		To:  "0.0.0.0/0",
		Via: "10.101.0.1",
	}, {
		To:  "::/0",
		Via: "fc00:101:ecec::1",
	}}
	require.Equal(t, routes, eth.Routes)
	updated, err := config.Apply(ctx, client)
	require.Nil(t, err)
	require.False(t, updated)

	// create a new file for a new interface (note this is not a valid config)
	eth = config.GetInterface("ens4", config2FileRoot)
	require.NotNil(t, eth)
	require.Equal(t, 2, len(config.NetplanFiles))
	require.Equal(t, 2, len(config.ethLookup))
	require.Equal(t, 0, len(eth.Addresses))
	require.Equal(t, 0, len(eth.Nameservers.Addresses))
	require.Equal(t, 0, len(eth.Routes))
	eth.Addresses = []string{"10.101.18.10/16", "2001:db8::10/64"}
	eth.Routes = []*NetplanRoute{{
		To:  "10.101.18.0/16",
		Via: "10.101.18.1",
	}, {
		To:  "2001:db8::/64",
		Via: "2001:db8::1",
	}}

	updated, err = config.Apply(ctx, client)
	require.Nil(t, err)
	require.True(t, updated)
	testutil.CompareExpectedFileData(t, config2FileRoot, "yaml", "")
	os.Remove(config2File)
}
