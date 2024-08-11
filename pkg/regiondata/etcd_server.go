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

// Run Etcd as a child process.
// May be useful for testing and initial development.

package regiondata

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
)

const EtcdLocalData string = "etcdLocal_data"
const EtcdLocalLog string = "etcdLocal.log"

func StartLocalEtcdServer(opts ...process.StartOp) (*process.Etcd, error) {
	_, filename, _, _ := runtime.Caller(0)
	testdir := filepath.Dir(filename) + "/" + EtcdLocalData

	etcd := &process.Etcd{
		Common: process.Common{
			Name: "etcd-local",
		},
		DataDir:        testdir,
		PeerAddrs:      "http://127.0.0.1:12379",
		ClientAddrs:    "http://127.0.0.1:12380",
		InitialCluster: "etcd-local=http://127.0.0.1:12379",
	}
	log.InfoLog("Starting local etcd", "clientUrls", etcd.ClientAddrs)
	err := etcd.StartLocal("", opts...)
	if err != nil {
		return nil, err
	}
	return etcd, nil
}

func StartLocalEtcdCluster(name string, nodes, startPort int, opts ...process.StartOp) ([]*process.Etcd, string, error) {
	procs := []*process.Etcd{}
	_, filename, _, _ := runtime.Caller(0)
	testdir := filepath.Dir(filename) + "/etcd-data-" + name

	names := []string{}
	peerAddrs := []string{}
	clientAddrs := []string{}
	for i := 0; i < nodes; i++ {
		names = append(names, fmt.Sprintf("%s%d", name, i))
		peerAddrs = append(peerAddrs, fmt.Sprintf("http://127.0.0.1:%d", startPort+i))
		clientAddrs = append(clientAddrs, fmt.Sprintf("http://127.0.0.1:%d", startPort+100+i))
	}
	clusterAddrs := []string{}
	for i := range names {
		clusterAddrs = append(clusterAddrs, names[i]+"="+peerAddrs[i])
	}
	cluster := strings.Join(clusterAddrs, ",")

	for i := 0; i < len(names); i++ {
		tag := strconv.Itoa(i)
		etcd := &process.Etcd{
			Common: process.Common{
				Name: names[i],
			},
			DataDir:        testdir + tag,
			PeerAddrs:      peerAddrs[i],
			ClientAddrs:    clientAddrs[i],
			InitialCluster: cluster,
		}
		log.InfoLog("Starting local etcd", "clientUrls", etcd.ClientAddrs)
		err := etcd.StartLocal("", opts...)
		if err != nil {
			return nil, "", err
		}
		procs = append(procs, etcd)
	}
	return procs, strings.Join(clientAddrs, ","), nil
}
