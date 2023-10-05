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

package confignode

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	intprocess "github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/version"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

const (
	DefaultCacheDir = "/root/crm_cache"
	// Platform services
	ServiceTypeCRM                = "crmserver"
	ServiceTypeShepherd           = "shepherd"
	ServiceTypeCloudletPrometheus = intprocess.PrometheusContainer
	K8sMasterNodeCount            = 1
	K8sWorkerNodeCount            = 2
	CRMRedisImage                 = "docker.io/bitnami/redis"
	CRMRedisVersion               = "6.2.6-debian-10-r103"
)

var PlatformServices = []string{
	ServiceTypeCRM,
	ServiceTypeShepherd,
	ServiceTypeCloudletPrometheus,
}

var ValidDockerArgs = map[string]string{
	"label":   "dict",
	"publish": "list",
	"volume":  "list",
}

type InfraApiAccess struct {
	ApiEndpoint string
	ApiGateway  string
}

func GetCommandArgs(cmdArgs []string) map[string]string {
	chefArgs := make(map[string]string)
	ii := 0
	for ii < len(cmdArgs) {
		if !strings.HasPrefix(cmdArgs[ii], "-") {
			continue
		}
		argKey := strings.TrimLeft(cmdArgs[ii], "-")
		argVal := ""
		ii += 1
		if ii < len(cmdArgs) && !strings.HasPrefix(cmdArgs[ii], "-") {
			argVal = cmdArgs[ii]
			ii += 1
		}
		chefArgs[argKey] = argVal
	}
	return chefArgs
}

func GetDockerArgs(cmdArgs []string) map[string]interface{} {
	chefArgs := make(map[string]interface{})
	ii := 0
	for ii < len(cmdArgs) {
		if !strings.HasPrefix(cmdArgs[ii], "-") {
			continue
		}
		argKey := strings.TrimLeft(cmdArgs[ii], "-")
		argVal := ""
		ii += 1
		if ii < len(cmdArgs) && !strings.HasPrefix(cmdArgs[ii], "-") {
			argVal = cmdArgs[ii]
			ii += 1
		}
		keyType := ""
		var ok bool
		if keyType, ok = ValidDockerArgs[argKey]; !ok {
			continue
		}
		if argKey == "label" {
			// argVal is format key=value or just key
			var dict map[string]string
			di, ok := chefArgs[argKey]
			if !ok {
				dict = map[string]string{}
				chefArgs[argKey] = dict
			} else {
				dict, _ = di.(map[string]string)
			}
			parts := strings.SplitN(argVal, "=", 2)
			key := parts[0]
			val := ""
			if len(parts) > 1 {
				val = parts[1]
			}
			dict[key] = val
		} else if keyType == "list" {
			newVal := []string{argVal}
			if existVal, ok := chefArgs[argKey]; ok {
				if eVal, ok := existVal.([]string); ok {
					newVal = append(newVal, eVal...)
				}
			}
			chefArgs[argKey] = newVal
		} else {
			chefArgs[argKey] = argVal
		}
	}
	return chefArgs
}

func GetCloudletAttributes(ctx context.Context, cl *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (map[string]interface{}, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletAttributes", "region", pfConfig.Region, "cloudletKey", cl.Key)

	// Make copy because this function modifies cloudlet
	cloudlet := *cl

	attributes := make(map[string]interface{})

	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		attributes["k8sNodeCount"] = K8sMasterNodeCount + K8sWorkerNodeCount
		if cloudlet.PlatformHighAvailability {
			// orchestration of platform services are done via the master, the arguments passed in individual nodes are not used. Redis
			// configuration therefore is done at the cloudlet level not the node level
			attributes["redisServiceName"] = rediscache.RedisHeadlessService
			attributes["redisServicePort"] = rediscache.RedisStandalonePort
			attributes["redisImage"] = CRMRedisImage
			attributes["redisVersion"] = CRMRedisVersion
		}
	}
	attributes["edgeCloudImage"] = pfConfig.ContainerRegistryPath
	attributes["edgeCloudVersion"] = pfConfig.PlatformTag
	attributes["notifyAddrs"] = pfConfig.NotifyCtrlAddrs

	attributes["mobiledgeXPackageVersion"] = version.MobiledgeXPackageVersion

	if pfConfig.ThanosRecvAddr != "" {
		attributes["thanosRecvAddr"] = pfConfig.ThanosRecvAddr
	}

	// Use default address if port is 0, as we'll have single
	// CRM instance here, hence there will be no port conflict
	if cloudlet.NotifySrvAddr == "127.0.0.1:0" {
		cloudlet.NotifySrvAddr = ""
	}

	pfConfig.CacheDir = DefaultCacheDir
	pfConfig.Span = ""

	for _, serviceType := range PlatformServices {
		serviceObj := make(map[string]interface{})
		var serviceCmdArgs []string
		var dockerArgs []string
		var envVars *map[string]string
		var err error
		switch serviceType {
		case ServiceTypeShepherd:
			serviceCmdArgs, envVars, err = intprocess.GetShepherdCmdArgs(&cloudlet, pfConfig)
			if err != nil {
				return nil, err
			}
			serviceCmdArgs = append([]string{"shepherd"}, serviceCmdArgs...)
		case ServiceTypeCRM:
			// Set container version to be empty, as it will be
			// present in edge-cloud image itself
			containerVersion := cloudlet.ContainerVersion
			cloudlet.ContainerVersion = ""
			// The HA role is not relevant here as chef will install both primary and secondary CRMs if HA is enabled and
			// change the HArole as required
			serviceCmdArgs, envVars, err = process.GetCRMCmdArgs(&cloudlet, pfConfig, process.HARolePrimary)
			if err != nil {
				return nil, err
			}
			serviceCmdArgs = append([]string{"crmserver"}, serviceCmdArgs...)
			if cloudlet.PlatformHighAvailability {
				serviceCmdArgs = append(serviceCmdArgs, "--redisStandaloneAddr", rediscache.RedisCloudletStandaloneAddr)
			}
			cloudlet.ContainerVersion = containerVersion
		case ServiceTypeCloudletPrometheus:
			// set image path for Promtheus
			serviceCmdArgs = intprocess.GetCloudletPrometheusCmdArgs()
			// docker args for prometheus
			dockerArgs = intprocess.GetCloudletPrometheusDockerArgs(&cloudlet, intprocess.GetCloudletPrometheusConfigHostFilePath())
			// env vars for promtheeus is empty for now
			envVars = &map[string]string{}

			attributes["prometheusImage"] = intprocess.PrometheusImagePath
			attributes["prometheusVersion"] = intprocess.PrometheusImageVersion
		default:
			return nil, fmt.Errorf("invalid service type: %s, valid service types are [%v]", serviceType, PlatformServices)
		}
		serviceObj["args"] = serviceCmdArgs
		chefDockerArgs := GetDockerArgs(dockerArgs)
		for k, v := range chefDockerArgs {
			serviceObj[k] = v
		}
		if envVars != nil {
			serviceObj["env"] = envVars
		}
		attributes[serviceType] = serviceObj
	}
	return attributes, nil
}
