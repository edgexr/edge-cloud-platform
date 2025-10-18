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

func TestParseHost(t *testing.T) {
	// Ensure that we can parse expected ImagePaths.
	// Note that we assume for docker apps, image path has had
	// k8smgmt.FixImagePath() run on it already, so that
	// the default docker registry has been added if it was
	// not specified.
	tests := []struct {
		in   string
		host string
		port string
		err  bool
	}{{
		"docker.io/library/ubuntu:18.04",
		"docker.io", "",
		false,
	}, {
		"ghcr.io/edgexr/nginxdemos-hello:0.4",
		"ghcr.io", "",
		false,
	}, {
		"https://charts.bitnami.com:8080/bitnami:bitnami/redis",
		"charts.bitnami.com", "8080",
		false,
	}, {
		"oci://ghcr.io/edgexr/postgresql",
		"ghcr.io", "",
		false,
	}, {
		"https://cloud-images.ubuntu.com/releases/oracular/release/ubuntu-24.10-server-cloudimg-amd64.img#md5:3d1d134d66318f982d32f02aec00fe879bfeb0338147b4038a25d1f9cddb527f",
		"cloud-images.ubuntu.com", "",
		false,
	}}
	for ii, test := range tests {
		host, port, err := ParseHost(test.in)
		if test.err {
			require.NotNil(t, err, "[%d] expected error for %s", ii, test.in)
		} else {
			require.Nil(t, err, "[%d] unexpected error for %s: %v", ii, test.in, err)
			require.Equal(t, test.host, host, "[%d] host mismatch for %s", ii, test.in)
			require.Equal(t, test.port, port, "[%d] port mismatch for %s", ii, test.in)
		}
	}
}
