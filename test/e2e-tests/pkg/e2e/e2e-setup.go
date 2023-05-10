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

package e2e

import (
	"io/ioutil"
	"log"
	"os/exec"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/mobiledgex/jaeger/plugin/storage/es/spanstore/dbmodel"
)

type DnsRecord struct {
	Name    string
	Type    string
	Content string
}

//cloudflare dns records
type CloudflareDNS struct {
	Zone    string
	Records []DnsRecord
}

// a comparison and yaml friendly version of AllMetrics for e2e-tests
type MetricsCompare struct {
	Name   string
	Tags   map[string]string
	Values map[string]float64
}

type OptimizedMetricsCompare struct {
	Name    string
	Tags    map[string]string
	Values  [][]string
	Columns []string
}

type MetricTargets struct {
	AppKey                 edgeproto.AppKey
	AppInstKey             edgeproto.AppInstKey
	ClusterInstKey         edgeproto.ClusterInstKey
	CloudletKey            edgeproto.CloudletKey
	LocationTileLatency    string // used for clientappusage and clientcloudletusage metrics to guarantee correct metric
	LocationTileDeviceInfo string // used for clientappusage and clientcloudletusage metrics to guarantee correct metric
}

type EventSearch struct {
	Search  node.EventSearch
	Results []node.EventData
}

type EventTerms struct {
	Search node.EventSearch
	Terms  *node.EventTerms
}

type SpanSearch struct {
	Search  node.SpanSearch
	Results []node.SpanOutCondensed
}

type SpanSearchVerbose struct {
	Search  node.SpanSearch
	Results []dbmodel.Span
}

type SpanTerms struct {
	Search node.SpanSearch
	Terms  *node.SpanTerms
}

// metrics that e2e currently tests for
var E2eAppSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
}

var E2eClusterSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
	"tcp",
	"udp",
}

var IgnoreTagValues = map[string]struct{}{
	cloudcommon.MetricTagDmeId: {},
}

// methods for dme-api metric
var ApiMethods = []string{
	"FindCloudlet",
	"PlatformFindCloudlet",
	"RegisterClient",
	"VerifyLocation",
}

var apiAddrsUpdated = false

func IsK8sDeployment() bool {
	return Deployment.Cluster.MexManifest != "" //TODO Azure
}

type ChefClient struct {
	NodeName   string   `yaml:"nodename"`
	JsonAttrs  string   `yaml:"jsonattrs"`
	ConfigFile string   `yaml:"configfile"`
	Runlist    []string `yaml:"runlist"`
}

// RunChefClient executes a single chef client run
func RunChefClient(apiFile string, vars map[string]string) error {
	chefClient := ChefClient{}
	err := ReadYamlFile(apiFile, &chefClient, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		if !IsYamlOk(err, "runchefclient") {
			log.Printf("error in unmarshal for file, %s\n", apiFile)
		}
		return err
	}
	var cmdargs = []string{
		"--node-name", chefClient.NodeName,
	}
	if chefClient.JsonAttrs != "" {
		err = ioutil.WriteFile("/tmp/chefattrs.json", []byte(chefClient.JsonAttrs), 0644)
		if err != nil {
			log.Printf("write to file failed, %s, %v\n", chefClient.JsonAttrs, err)
			return err
		}
		cmdargs = append(cmdargs, "-j", "/tmp/chefattrs.json")
	}
	if chefClient.Runlist != nil {
		runlistStr := strings.Join(chefClient.Runlist, ",")
		cmdargs = append(cmdargs, "--runlist", runlistStr)
	}
	cmdargs = append(cmdargs, "-c", chefClient.ConfigFile)
	cmd := exec.Command("chef-client", cmdargs[0:]...)
	output, err := cmd.CombinedOutput()
	log.Printf("chef-client run with args: %v output:\n%v\n", cmdargs, string(output))
	if err != nil {
		log.Printf("Failed to run chef client, %v\n", err)
		return err
	}
	return nil
}
