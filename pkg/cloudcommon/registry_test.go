package cloudcommon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseImgUrl(t *testing.T) {
	tests := []struct {
		imgurl  string
		expErr  string
		expHost string
		expOrg  string
	}{{
		"docker.cloud.ec.org/edgedev/http-echo:0.2.3",
		"",
		"docker.cloud.ec.org",
		"edgedev",
	}, {
		"https://console.cloud.ec.org/storage/v1/artifacts/edgecloudorg/edgecloud-v5.0.0.qcow2",
		"",
		"console.cloud.ec.org",
		"edgecloudorg",
	}}
	for _, test := range tests {
		host, org, err := parseImageUrl(test.imgurl)
		if test.expErr == "" {
			require.Nil(t, err)
			require.Equal(t, test.expHost, host)
			require.Equal(t, test.expOrg, org)
		} else {
			require.NotNil(t, err)
			require.Contains(t, err.Error(), test.expErr)
		}
	}
}
