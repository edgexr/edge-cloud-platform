package chefmgmt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-chef/chef"
	"github.com/mitchellh/mapstructure"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

const (
	// Chef Policies
	ChefPolicyBase   = "base"
	ChefPolicyDocker = "docker_crm"
	ChefPolicyK8s    = "k8s_crm"

	DefaultChefServerPath = "https://chef.mobiledgex.net/organizations/mobiledgex"
)

var ValidDockerArgs = map[string]string{
	"label":   "list",
	"publish": "string",
	"volume":  "list",
}

type VMChefParams struct {
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

const (
	ResourceDockerRegistry  = "docker_registry"
	ResourceDockerImage     = "docker_image"
	ResourceDockerContainer = "docker_container"
)

func GetChefAuthKeys(ctx context.Context, vaultConfig *vault.Config) (*ChefAuthKey, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "fetch chef auth keys")
	vaultPath := "/secret/data/accounts/chef"
	auth := &ChefAuthKey{}
	err := vault.GetData(vaultConfig, vaultPath, 0, auth)
	if err != nil {
		return nil, fmt.Errorf("Unable to find chef auth keys from vault path %s, %v", vaultPath, err)
	}
	if auth.ApiKey == "" {
		return nil, fmt.Errorf("Unable to find chef API key")
	}
	return auth, nil
}

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

func ChefClientRunStatus(ctx context.Context, client *chef.Client, clientName string, startTime time.Time) ([]ChefStatusInfo, error) {
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

func ChefClientCreate(ctx context.Context, client *chef.Client, chefParams *VMChefParams) (string, error) {
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
	err := ChefClientDelete(ctx, client, clientName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "delete any stale chef clients", "err", err)
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "chef client create", "client name", clientName, "params", *chefParams)
	clientObj := chef.ApiNewClient{
		Name:      clientName,
		Validator: false,
		Admin:     false,
		CreateKey: true,
	}
	out, err := client.Clients.Create(clientObj)
	if err != nil {
		return "", fmt.Errorf("failed to create client %s: %v", clientName, err)
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
