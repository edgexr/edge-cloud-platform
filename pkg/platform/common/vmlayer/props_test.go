package vmlayer

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/stretchr/testify/require"
)

func TestGetMetalLBIPV6RangeFromMasterIP(t *testing.T) {
	ctx := context.Background()
	vp := VMProperties{}
	vp.CommonPf.Properties.Init()
	tests := []struct {
		masterIP  string
		rangeVal  string
		expOut    string
		expErrStr string
	}{{
		"fc00:101::1",
		"ffff:ffff:ffff:0-ffff:ffff:ffff:fff0",
		"fc00:101::ffff:ffff:ffff:0-fc00:101::ffff:ffff:ffff:fff0",
		"",
	}, {
		"fc00:101:ecec::1",
		"ffff:ffff:ffff:0-ffff:ffff:ffff:fff0",
		"fc00:101:ecec:0:ffff:ffff:ffff:0-fc00:101:ecec:0:ffff:ffff:ffff:fff0",
		"",
	}, {
		"fc00:101:ecec:808:efef:a1a1:abcd:12",
		"ffff:ffff:ffff:0000-ffff:ffff:ffff:fff0",
		"fc00:101:ecec:808:ffff:ffff:ffff:0-fc00:101:ecec:808:ffff:ffff:ffff:fff0",
		"",
	}}
	for _, test := range tests {
		vp.CommonPf.Properties.Properties["MEX_METALLB_IPV6_RANGE"] = &edgeproto.PropertyInfo{
			Value: test.rangeVal,
		}
		out, err := vp.GetMetalLBIPV6RangeFromMasterIp(ctx, test.masterIP)
		if test.expErrStr == "" {
			require.Nil(t, err)
			require.Equal(t, test.expOut, out)
		} else {
			require.NotNil(t, err)
			require.Contains(t, err.Error(), test.expErrStr)
		}
	}
}
