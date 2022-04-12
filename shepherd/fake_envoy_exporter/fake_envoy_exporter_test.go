// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExporter(t *testing.T) {
	*sockFile = "/tmp/fake_envoy_exporter_unit_test"
	portFlags = append(portFlags, "80")

	ch := make(chan bool, 0)
	run(ch)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", *sockFile)
			},
		},
	}

	ensureMeas(t, client, `envoy_cluster_upstream_cx_active{envoy_cluster_name="backend80"} 50`)

	// update measure
	params := url.Values{}
	params.Set("measure", `envoy_cluster_upstream_cx_active{envoy_cluster_name="backend80"}`)
	params.Set("val", "11")
	resp, err := client.PostForm("http://unix/setval", params)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	ensureMeas(t, client, `envoy_cluster_upstream_cx_active{envoy_cluster_name="backend80"} 11`)

	// clear measure
	params = url.Values{}
	params.Set("measure", `envoy_cluster_upstream_cx_active{envoy_cluster_name="backend80"}`)
	params.Set("val", "0")
	resp, err = client.PostForm("http://unix/setval", params)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	ensureMeas(t, client, `envoy_cluster_upstream_cx_active{envoy_cluster_name="backend80"} 0`)
}

func ensureMeas(t *testing.T, client *http.Client, meas string) {
	resp, err := client.Get("http://unix/stats/prometheus")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	dat, err := ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	// rather than check the whole data, just check length and one part
	arr := strings.Split(string(dat), "\n")
	require.Greater(t, len(arr), 600)

	found := false
	for _, str := range arr {
		if str == meas {
			found = true
			break
		}
	}
	require.True(t, found, "searched:\n%s", strings.Join(arr, "\n"))
}
