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

package influxq_testutil

import (
	"os"
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/stretchr/testify/require"
)

// Helper function to start influxd
// Must be called before Controller startServices()
// After calling this function, should call defer p.StopLocal() to clean up if return value is non-nil
func StartInfluxd(t *testing.T) *process.Influx {
	// Allow multiple influxDBs to run in parallel
	// from different unit test packages.
	// By default, tests within a package run in serial,
	// but tests from different packages may run in parallel.
	dir, err := os.Getwd()
	require.Nil(t, err)

	p := &process.Influx{}
	p.Common.Name = "influx-test"
	// addresses are hard-coded per package
	if strings.HasSuffix(dir, "cmd/controller") {
		p.HttpAddr = "127.0.0.1:8186"
		p.BindAddr = "127.0.0.1:8187"
	} else if strings.HasSuffix(dir, "cmd/controller/influxq_client") {
		p.HttpAddr = "127.0.0.1:8188"
		p.BindAddr = "127.0.0.1:8189"
	} else {
		require.True(t, false, "No addresses defined for path %s", dir)
	}
	p.DataDir = dir + "/.influxdb"
	logfile := dir + "/influxdb.log"
	log.DebugLog(log.DebugLevelInfo, "Starting new influxDB instance", "pkg", dir, "p", p)
	// start influx
	err = p.StartLocal(logfile, process.WithCleanStartup())
	require.Nil(t, err, "start InfluxDB server")
	return p
}
