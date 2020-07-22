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
	*cluster = "testclust"

	ch := make(chan bool, 0)
	run(ch)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", *sockFile)
			},
		},
	}

	ensureMeas(t, client, `envoy_cluster_upstream_cx_active{envoy_cluster_name="testclust"} 50`)

	// update measure
	params := url.Values{}
	params.Set("measure", `envoy_cluster_upstream_cx_active{envoy_cluster_name="testclust"}`)
	params.Set("val", "11")
	resp, err := client.PostForm("http://unix/setval", params)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	ensureMeas(t, client, `envoy_cluster_upstream_cx_active{envoy_cluster_name="testclust"} 11`)
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
