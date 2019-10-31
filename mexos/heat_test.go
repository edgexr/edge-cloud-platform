package mexos

import (
	"strings"
	"testing"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/stretchr/testify/require"
)

func TestHeatNodePrefix(t *testing.T) {
	data := []struct {
		name string
		num  uint32
	}{
		{cloudcommon.MexNodePrefix + "1", 1},
		{cloudcommon.MexNodePrefix + "5", 5},
		{cloudcommon.MexNodePrefix + "15", 15},
		{cloudcommon.MexNodePrefix + "548934", 548934},
		{cloudcommon.MexNodePrefix + "15x", 15},
		{cloudcommon.MexNodePrefix + "15h", 15},
		{cloudcommon.MexNodePrefix + "15a", 15},
		{cloudcommon.MexNodePrefix + "15-asdf", 15},
		{cloudcommon.MexNodePrefix + "15%!@#$%^&*()1", 15},
		{cloudcommon.MexNodePrefix + "15" + cloudcommon.MexNodePrefix + "35", 15},
	}
	for _, d := range data {
		ok, num := ParseHeatNodePrefix(d.name)
		require.True(t, ok, "matched %s", d.name)
		require.Equal(t, d.num, num, "matched num for %s", d.name)
		// make sure prefix gen function works
		prefix := HeatNodePrefix(d.num)
		ok = strings.HasPrefix(d.name, prefix)
		require.True(t, ok, "%s has prefix %s", d.name, prefix)
	}
	bad := []string{
		cloudcommon.MexNodePrefix,
		"a" + cloudcommon.MexNodePrefix + "1",
		cloudcommon.MexNodePrefix + "-1",
		"mex-k8s-master-clust-cloudlet-1",
		"mex-k8s-nod-1",
	}
	for _, b := range bad {
		ok, _ := ParseHeatNodePrefix(b)
		require.False(t, ok, "should not match %s", b)
	}
}
