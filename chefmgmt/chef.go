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

package chefmgmt

import (
	"context"
	"fmt"
	"strings"
	"time"

	intprocess "github.com/edgexr/edge-cloud-infra/e2e-tests/int-process"
	"github.com/edgexr/edge-cloud-infra/version"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/integration/process"
	"github.com/edgexr/edge-cloud/rediscache"
	"github.com/edgexr/edge-cloud/util"

	"github.com/go-chef/chef"
	"github.com/mitchellh/mapstructure"
	"github.com/edgexr/edge-cloud/log"
)

const (
	// Chef Policies
	ChefPolicyBase        = "base"
	ChefPolicyDocker      = "docker_crm"
	ChefPolicyK8s         = "k8s_crm"
	ChefPolicyK8sWorker   = "k8s_worker_crm"
	DefaultChefServerPath = "https://chef.mobiledgex.net/organizations/mobiledgex"
	DefaultCacheDir       = "/root/crm_cache"
)

const (
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
	"label":   "list",
	"publish": "string",
	"volume":  "list",
}

type ServerChefParams struct {
	NodeName    string
	ServerPath  string
	ClientKey   string
	Attributes  map[string]interface{}
	PolicyName  string
	PolicyGroup string
}

type ChefAuthKey struct {
	ApiKey        string `json:"apikey"`
	ValidationKey string `json:"validationkey"`
}

type ChefResource struct {
	CookbookName string   `mapstructure:"cookbook_name"`
	RecipeName   string   `mapstructure:"recipe_name"`
	Action       []string `mapstructure:"action"`
	Resource     string   `mapstructure:"resource"`
	ResourceType string   `mapstructure:"resource_type"`
	Updated      bool     `mapstructure:"updated"`
}

type ChefRunStatus struct {
	Status    string         `mapstructure:"status"`
	Start     string         `mapstructure:"start"`
	End       string         `mapstructure:"end"`
	Backtrace []string       `mapstructure:"backtrace"`
	Exception string         `mapstructure:"exception"`
	Resources []ChefResource `mapstructure:"resources"`
}

type ChefStatusInfo struct {
	Message string
	Failed  bool
}

type ChefApiAccess struct {
	ApiEndpoint string
	ApiGateway  string
}

type ChefNodeInfo struct {
	NodeName string
	NodeType cloudcommon.NodeType
	Policy   string
}

const (
	ResourceDockerRegistry  = "docker_registry"
	ResourceDockerImage     = "docker_image"
	ResourceDockerContainer = "docker_container"

	ResourceChefClientUpdater = "update chef-client"
)

func GetChefClient(ctx context.Context, apiKey, chefServerPath string) (*chef.Client, error) {
	if chefServerPath == "" {
		chefServerPath = DefaultChefServerPath
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "get chef client", "chefServerPath", chefServerPath)
	if !strings.HasSuffix(chefServerPath, "/") {
		chefServerPath = chefServerPath + "/"
	}
	client, err := chef.NewClient(&chef.Config{
		Name:    "chefadmin",
		Key:     apiKey,
		SkipSSL: false,
		BaseURL: chefServerPath,
	})
	if err != nil {
		return nil, fmt.Errorf("Unable to setup chef client: %v", err)
	}
	return client, nil
}

func ChefRoleExists(ctx context.Context, client *chef.Client, roleName string) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "check if chef role exists", "role name", roleName)
	roleList, err := client.Roles.List()
	if err != nil {
		return false, fmt.Errorf("Unable to get chef roles: %v", err)
	}
	for k, _ := range *roleList {
		if k == roleName {
			return true, nil
		}
	}
	return false, nil
}

func ChefClientExists(ctx context.Context, client *chef.Client, clientName string) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "check if chef client exists", "client name", clientName)
	clientList, err := client.Clients.List()
	if err != nil {
		return false, fmt.Errorf("Unable to get chef clients: %v", err)
	}
	for k, _ := range clientList {
		if k == clientName {
			return true, nil
		}
	}
	return false, nil
}

func ChefClientDelete(ctx context.Context, client *chef.Client, clientName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "delete chef client", "client name", clientName)
	clientList, err := client.Clients.List()
	if err != nil {
		return fmt.Errorf("Unable to get chef clients: %v", err)
	}
	for k, _ := range clientList {
		if k == clientName {
			err = client.Clients.Delete(k)
			if err != nil {
				return err
			}
			break
		}
	}
	nodeList, err := client.Nodes.List()
	if err != nil {
		return fmt.Errorf("unable to get chef nodes: %v", err)
	}
	for k, _ := range nodeList {
		if k == clientName {
			return client.Nodes.Delete(k)
		}
	}
	return nil
}

func ChefClientRunStatus(ctx context.Context, client *chef.Client, clientName string) ([]ChefStatusInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "fetch chef client's run status", "client name", clientName)
	nodeInfo, err := client.Nodes.Get(clientName)
	if err != nil {
		return nil, fmt.Errorf("Unable to get chef node info: %s, %v", clientName, err)
	}
	if _, ok := nodeInfo.NormalAttributes["runstatus"]; !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find runstatus attributes")
		return nil, nil
	}
	runStatusAttr := nodeInfo.NormalAttributes["runstatus"]

	var runStatus ChefRunStatus
	err = mapstructure.Decode(runStatusAttr, &runStatus)
	if err != nil {
		return nil, fmt.Errorf("unable to decode runstatus attributes: %s, error: %v", runStatusAttr, err)
	}

	failed := false
	var statusInfo []ChefStatusInfo
	for ii, res := range runStatus.Resources {
		msg := ""
		switch res.ResourceType {
		case ResourceDockerRegistry:
			msg = "Log in to docker registry"
		case ResourceDockerImage:
			msg = "Fetch docker image to start cloudlet services"
		case ResourceDockerContainer:
			msg = fmt.Sprintf("Start %s", res.Resource)
		default:
			msg = res.Resource
		}

		if ii == len(runStatus.Resources)-1 && runStatus.Exception != "" {
			if msg == ResourceChefClientUpdater && runStatus.Exception == "exit" {
				// Ignore failure from chef-client updater. On a successful run, the cookbook
				// aborts the current chef-client run to reload the new upgraded chef-client,
				// but then this gets treated as a failure here. Hence we ignore it.
				// In case, it is a valid error, this can be fixed using knife commands.
				// It doesn't have to block cloudlet bringup, we can just log it
				log.SpanLog(ctx, log.DebugLevelInfra, "ignore chef-client exit exception as chef-client is updating", "exception", runStatus.Exception)
				continue
			}
			msg = fmt.Sprintf("Failed to %s", msg)
			failed = true
			log.SpanLog(ctx, log.DebugLevelInfra, "failure message from chef node run status", "message", msg, "exception", runStatus.Exception)
		}

		if !failed && !res.Updated {
			log.SpanLog(ctx, log.DebugLevelInfra, "skipping chef node status as it is not executed", "message", msg)
			continue
		}

		statusInfo = append(statusInfo, ChefStatusInfo{
			Message: msg,
			Failed:  failed,
		})
	}
	return statusInfo, nil
}

func ChefClientCreate(ctx context.Context, client *chef.Client, chefParams *ServerChefParams) (string, error) {
	if chefParams == nil {
		return "", fmt.Errorf("unable to get chef params")
	}

	localMode := false
	if client.BaseURL != nil {
		if strings.Contains(client.BaseURL.Host, "127.0.0.1") {
			// chef server running locally
			localMode = true
		}
	}

	clientName := chefParams.NodeName
	log.SpanLog(ctx, log.DebugLevelInfra, "chef client create", "client name", clientName, "params", *chefParams)
	clientObj := chef.ApiNewClient{
		Name:      clientName,
		Validator: false,
		Admin:     false,
		CreateKey: true,
	}
	out, err := client.Clients.Create(clientObj)
	if err != nil {
		if strings.Contains(err.Error(), " 409") {
			log.SpanLog(ctx, log.DebugLevelInfra, "chef client already exists, deleting and trying again", "client name", clientName)
			err = ChefClientDelete(ctx, client, clientName)
			if err != nil {
				return "", err
			}
			out, err = client.Clients.Create(clientObj)
			if err != nil {
				return "", fmt.Errorf("failed to create client after delete and retry %s: %v", clientName, err)
			}
		} else {
			return "", fmt.Errorf("failed to create client %s: %v", clientName, err)
		}
	}
	clientKey := out.ChefKey.PrivateKey
	if clientKey == "" {
		return "", fmt.Errorf("unable to get private key of the client %s", clientName)
	}

	nodeObj := chef.Node{
		Name:             clientName,
		Environment:      "",
		ChefType:         "node",
		JsonClass:        "Chef::Node",
		NormalAttributes: chefParams.Attributes,
	}
	// In local mode, don't use policyfile, this gives us flexibility in our testing
	if !localMode {
		nodeObj.PolicyName = chefParams.PolicyName
		nodeObj.PolicyGroup = chefParams.PolicyGroup
	}
	_, err = client.Nodes.Post(nodeObj)
	if err != nil {
		return "", fmt.Errorf("failed to create node %s: %v", clientName, err)
	}

	aclTypes := []string{"update", "create", "delete", "read"}
	for _, aclType := range aclTypes {
		acl := &chef.ACL{
			aclType: chef.ACLitems{
				Groups: chef.ACLitem{"admins", chefParams.PolicyGroup},
				Actors: chef.ACLitem{clientName},
			},
		}
		err = client.ACLs.Put("nodes", clientName, aclType, acl)
		if err != nil {
			return "", fmt.Errorf("unable to add %s acl for node %s", aclType, clientName)
		}
		err = client.ACLs.Put("clients", clientName, aclType, acl)
		if err != nil {
			return "", fmt.Errorf("unable to add %s acl for client %s", aclType, clientName)
		}
	}

	return clientKey, nil
}

func GetChefArgs(cmdArgs []string) map[string]string {
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

func GetChefDockerArgs(cmdArgs []string) map[string]interface{} {
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
			// Chef docker cookbook requires label to in format key:val
			// But docker requires it in format key=val.
			// Hence the special handling
			argVal = strings.Replace(argVal, "=", ":", 1)
		}
		if keyType == "list" {
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

func ChefPolicyGroupList(ctx context.Context, client *chef.Client) ([]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "chef policy group list")
	policies, err := client.PolicyGroups.List()
	if err != nil {
		return nil, fmt.Errorf("failed to get list of chef policy groups: %v", err)
	}

	policyGroups := []string{}
	for groupName, _ := range policies {
		policyGroups = append(policyGroups, groupName)
	}
	return policyGroups, nil
}

func GetChefRunStatus(ctx context.Context, chefClient *chef.Client, clientName string, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	// Fetch chef run list status
	var err error
	updateCallback(edgeproto.UpdateTask, "Waiting for run lists to be executed on Platform Server")
	timeout := time.After(20 * time.Minute)
	tick := time.Tick(5 * time.Second)
	runListTime := time.Now()

	for {
		var statusInfo []ChefStatusInfo
		select {
		case <-timeout:
			log.SpanLog(ctx, log.DebugLevelInfra, "getChefRunStatus timeout", "cloudletName", cloudlet.Key.Name)
			return fmt.Errorf("timed out waiting for platform Server to connect to Chef Server")
		case <-tick:
			statusInfo, err = ChefClientRunStatus(ctx, chefClient, clientName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "getChefRunStatus ChefClientRunStatus error", "cloudletName", cloudlet.Key.Name, "error", err)
				return err
			}
		}
		if len(statusInfo) > 0 {
			updateCallback(edgeproto.UpdateTask, "Performed following actions:")
			for _, info := range statusInfo {
				if info.Failed {
					return fmt.Errorf(info.Message)
				}
				updateCallback(edgeproto.UpdateStep, info.Message)
			}
			break
		}
	}
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Wait run list complete time: %s", cloudcommon.FormatDuration(time.Since(runListTime), 2)))
	return nil
}

func GetChefCloudletTags(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, nodeType cloudcommon.NodeType) []string {
	return []string{
		"deploytag/" + pfConfig.DeploymentTag,
		"region/" + pfConfig.Region,
		"cloudlet/" + cloudlet.Key.Name,
		"cloudletorg/" + cloudlet.Key.Organization,
		"nodetype/" + nodeType.String(),
	}
}

func GetChefCloudletAttributes(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, nodeType cloudcommon.NodeType) (map[string]interface{}, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetChefCloudletAttributes", "region", pfConfig.Region, "cloudletKey", cloudlet.Key)

	chefAttributes := make(map[string]interface{})

	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		chefAttributes["k8sNodeCount"] = K8sMasterNodeCount + K8sWorkerNodeCount
		if cloudlet.PlatformHighAvailability {
			// orchestration of platform services are done via the master, the arguments passed in individual nodes are not used. Redis
			// configuration therefore is done at the cloudlet level not the node level
			chefAttributes["redisServiceName"] = rediscache.RedisHeadlessService
			chefAttributes["redisServicePort"] = rediscache.RedisStandalonePort
			chefAttributes["redisImage"] = CRMRedisImage
			chefAttributes["redisVersion"] = CRMRedisVersion
		}
	}
	chefAttributes["edgeCloudImage"] = pfConfig.ContainerRegistryPath
	chefAttributes["edgeCloudVersion"] = cloudlet.ContainerVersion
	if cloudlet.OverridePolicyContainerVersion {
		chefAttributes["edgeCloudVersionOverride"] = cloudlet.ContainerVersion
	}
	chefAttributes["notifyAddrs"] = pfConfig.NotifyCtrlAddrs

	chefAttributes["tags"] = GetChefCloudletTags(cloudlet, pfConfig, nodeType)

	chefAttributes["mobiledgeXPackageVersion"] = version.MobiledgeXPackageVersion

	// Use default address if port is 0, as we'll have single
	// CRM instance here, hence there will be no port conflict
	if cloudlet.NotifySrvAddr == "127.0.0.1:0" {
		cloudlet.NotifySrvAddr = ""
	}

	pfConfig.CacheDir = DefaultCacheDir

	for _, serviceType := range PlatformServices {
		serviceObj := make(map[string]interface{})
		var serviceCmdArgs []string
		var dockerArgs []string
		var envVars *map[string]string
		var err error
		switch serviceType {
		case ServiceTypeShepherd:
			serviceCmdArgs, envVars, err = intprocess.GetShepherdCmdArgs(cloudlet, pfConfig)
			if err != nil {
				return nil, err
			}
		case ServiceTypeCRM:
			// Set container version to be empty, as it will be
			// present in edge-cloud image itself
			containerVersion := cloudlet.ContainerVersion
			cloudlet.ContainerVersion = ""
			// The HA role is not relevant here as chef will install both primary and secondary CRMs if HA is enabled and
			// change the HArole as required
			serviceCmdArgs, envVars, err = cloudcommon.GetCRMCmdArgs(cloudlet, pfConfig, process.HARolePrimary)
			if err != nil {
				return nil, err
			}
			if cloudlet.PlatformHighAvailability {
				serviceCmdArgs = append(serviceCmdArgs, "--redisStandaloneAddr", rediscache.RedisCloudletStandaloneAddr)
			}
			cloudlet.ContainerVersion = containerVersion
		case ServiceTypeCloudletPrometheus:
			// set image path for Promtheus
			serviceCmdArgs = intprocess.GetCloudletPrometheusCmdArgs()
			// docker args for prometheus
			dockerArgs = intprocess.GetCloudletPrometheusDockerArgs(cloudlet, intprocess.GetCloudletPrometheusConfigHostFilePath())
			// env vars for promtheeus is empty for now
			envVars = &map[string]string{}

			chefAttributes["prometheusImage"] = intprocess.PrometheusImagePath
			chefAttributes["prometheusVersion"] = intprocess.PrometheusImageVersion
		default:
			return nil, fmt.Errorf("invalid service type: %s, valid service types are [%v]", serviceType, PlatformServices)
		}
		chefArgs := GetChefArgs(serviceCmdArgs)
		serviceObj["args"] = chefArgs
		chefDockerArgs := GetChefDockerArgs(dockerArgs)
		for k, v := range chefDockerArgs {
			serviceObj[k] = v
		}
		if envVars != nil {
			envVarArr := []string{}
			for k, v := range *envVars {
				envVar := fmt.Sprintf("%s=%s", k, v)
				envVarArr = append(envVarArr, envVar)
			}
			serviceObj["env"] = envVarArr
		}
		chefAttributes[serviceType] = serviceObj
	}
	return chefAttributes, nil
}

func GetChefPlatformAttributes(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, nodeInfo *ChefNodeInfo, apiAccess *ChefApiAccess, cloudletNodes []ChefNodeInfo) (map[string]interface{}, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetChefPlatformAttributes", "region", pfConfig.Region, "nodeInfo", nodeInfo, "cloudletKey", cloudlet.Key, "PhysicalName", cloudlet.PhysicalName)

	chefAttributes, err := GetChefCloudletAttributes(ctx, cloudlet, pfConfig, nodeInfo.NodeType)
	if err != nil {
		return nil, err
	}
	if nodeInfo.Policy == ChefPolicyBase {
		return chefAttributes, nil
	}

	if apiAccess.ApiEndpoint != "" {
		urlObj, err := util.ImagePathParse(apiAccess.ApiEndpoint)
		if err != nil {
			return nil, err
		}
		hostname := strings.Split(urlObj.Host, ":")
		if len(hostname) != 2 {
			return nil, fmt.Errorf("invalid api endpoint addr: %s", apiAccess.ApiEndpoint)
		}
		// API Endpoint address might have hostname in it, hence resolve the addr
		endpointIp, err := cloudcommon.LookupDNS(hostname[0])
		if err != nil {
			return nil, err
		}
		chefAttributes["infraApiAddr"] = endpointIp
		chefAttributes["infraApiPort"] = hostname[1]
		if apiAccess.ApiGateway != "" {
			chefAttributes["infraApiGw"] = apiAccess.ApiGateway
		}
	}
	for _, node := range cloudletNodes {
		chefAttributes[node.NodeType.String()] = node.NodeName
	}
	return chefAttributes, nil
}
