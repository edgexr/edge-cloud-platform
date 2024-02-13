// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
