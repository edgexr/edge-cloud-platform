package mccli

import (
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/stretchr/testify/require"
)

func TestUpdateFields(t *testing.T) {
	rc := RootCommand{}
	apiCmd := ormctl.MustGetCommand("UpdateClusterInst")
	cliCmd := rc.ConvertCmd(apiCmd)
	args := []string{
		"region=local",
		"cluster=clust1",
		"cluster-org=devOrg",
		"cloudlet=dmuus-cloud-1",
		"cloudlet-org=dmuus",
		"numnodes=2",
	}
	in, err := cliCmd.ParseInput(args)
	require.Nil(t, err)
	ormctl.SetUpdateClusterInstFields(in)
	obj, ok := in["ClusterInst"]
	require.True(t, ok)
	objmap, ok := obj.(map[string]interface{})
	require.True(t, ok)
	fields, ok := objmap["fields"]
	require.True(t, ok)
	require.ElementsMatch(t, []string{"2.1.1", "2.3", "2.2.1", "2.2.2", "14"}, fields)
}
