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

package k8smgmt

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/deployvars"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

// this is an initial set of supported helm install options
var validHelmInstallOpts = map[string]struct{}{
	"version":  struct{}{},
	"timeout":  struct{}{},
	"wait":     struct{}{},
	"verify":   struct{}{},
	"username": struct{}{},
}

func getHelmOpts(ctx context.Context, client ssh.Client, appName, delims string, configs []*edgeproto.ConfigFile) (string, error) {
	var ymls []string

	deploymentVars, varsFound := ctx.Value(deployvars.DeploymentReplaceVarsKey).(*deployvars.DeploymentReplaceVars)
	// Walk the Configs in the App and generate the yaml files from the helm customization ones
	for ii, v := range configs {
		// skip non helm and empty configs
		if v.Kind == edgeproto.AppConfigHelmYaml && v.Config != "" {
			// config can either be remote, or local
			cfg, err := cloudcommon.GetDeploymentManifest(ctx, nil, v.Config)
			if err != nil {
				return "", err
			}
			// Fill in the Deployment Vars passed as a variable through the context
			if varsFound {
				cfg, err = deployvars.ReplaceDeploymentVars(cfg, delims, deploymentVars)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "failed to replace Crm variables",
						"config file", v.Config, "DeploymentVars", deploymentVars, "error", err)
					return "", err
				}
			}
			file := fmt.Sprintf("%s%d", appName, ii)
			err = pc.WriteFile(client, file, cfg, v.Kind, pc.NoSudo)
			if err != nil {
				return "", err
			}
			ymls = append(ymls, file)
		}
	}
	return getHelmYamlOpt(ymls), nil
}

func getHelmNamespaceArgs(namespace string, action cloudcommon.Action) string {
	if namespace == "" {
		return ""
	}
	args := "--namespace=" + namespace
	if action == cloudcommon.Create {
		args += " --create-namespace"
	}
	return args
}

// helm chart install options are passed as app annotations.
// Example: "version=1.2.2,wait=true,timeout=60" would result in "--version 1.2.2 --wait --timeout 60"
func getHelmInstallOptsString(annotations string) (string, error) {
	outArr := []string{}
	if annotations == "" {
		return "", nil
	}
	// Prevent possible cross-scripting
	invalidChar := strings.IndexAny(annotations, ";`")
	if invalidChar != -1 {
		return "", fmt.Errorf("\"%c\" not allowed in annotations", annotations[invalidChar])
	}
	opts := strings.Split(annotations, ",")
	for _, v := range opts {
		// split by '='
		nameVal := strings.Split(v, "=")
		if len(nameVal) < 2 {
			return "", fmt.Errorf("Invalid annotations string <%s>", annotations)
		}
		// case of "wait=true", true, should not be passed
		if nameVal[1] == "true" {
			nameVal = nameVal[:1]
		} else {
			// make sure that all strings are quoted
			nameVal[1] = strings.TrimSpace(nameVal[1])
			if _, err := strconv.ParseFloat(nameVal[1], 64); err != nil {
				nameVal[1] = strconv.Quote(nameVal[1])
			}
		}
		nameVal[0] = strings.TrimSpace(nameVal[0])
		// validate that the option is one of the supported ones
		if _, found := validHelmInstallOpts[nameVal[0]]; !found {
			return "", fmt.Errorf("Invalid install option passed <%s>", nameVal[0])
		}
		// prepend '--' to the flag
		nameVal[0] = "--" + nameVal[0]
		outArr = append(outArr, nameVal...)
	}
	return strings.Join(outArr, " "), nil
}

type HelmChartSpec struct {
	// Original image path from the App
	ImagePath string
	// The URL portion of the spec, may be http(s) or oci
	URLPath string
	// The repo name for an http url
	RepoName string
	// The chart name for an http url
	ChartName string
	// The reference to the chart to be used in helm install/upgrade
	ChartRef string
}

// GetHelmChartSpec parses the image path and extracs the helm chart information.
// There are two types of charts:
// 1. repo add: "https://resources.gigaspaces.com/helm-charts:gigaspaces/insightedge"
// repo name is "gigaspaces" and path is "https://resources.gigaspaces.com/helm-charts"
// 2. OCI path: "oci://registry-1.docker.io/bitnamicharts/nginx"
func GetHelmChartSpec(imagePath string) (*HelmChartSpec, error) {
	spec := &HelmChartSpec{
		ImagePath: imagePath,
	}
	if strings.HasPrefix(imagePath, "http") {
		// break off ending repo/chart
		expectedHTTPFormat := "<repoURL>:<repo-name>/<chart-name>"
		idx := strings.LastIndex(imagePath, ":")
		if idx == -1 {
			return nil, fmt.Errorf("missing repo/chart in helm image path %q, expected format %q", imagePath, expectedHTTPFormat)
		}
		spec.URLPath = imagePath[:idx]
		if spec.URLPath == "" {
			return nil, fmt.Errorf("missing repo URL in helm image path %q, expected format %q", imagePath, expectedHTTPFormat)
		}
		// check syntax of URL
		_, err := url.Parse(spec.URLPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse helm image path URL %q, %w", imagePath, err)
		}
		chartParts := strings.Split(imagePath[idx+1:], "/")
		if len(chartParts) != 2 {
			return nil, fmt.Errorf("invalid repo/chart in helm image path %q, expected format %q", imagePath, expectedHTTPFormat)
		}
		spec.RepoName = chartParts[0]
		spec.ChartName = chartParts[1]
		if spec.RepoName == "" {
			return nil, fmt.Errorf("empty repo name in helm image path %q, expected format %q", imagePath, expectedHTTPFormat)
		}
		if spec.ChartName == "" {
			return nil, fmt.Errorf("empty chart name in helm image path %q, expected format %q", imagePath, expectedHTTPFormat)
		}
		spec.ChartRef = fmt.Sprintf("%s/%s", spec.RepoName, spec.ChartName)
	} else if strings.HasPrefix(imagePath, "oci://") {
		_, err := url.Parse(imagePath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse helm image path URL %q, %w", imagePath, err)
		}
		spec.URLPath = imagePath
		spec.ChartRef = imagePath
	} else {
		return nil, fmt.Errorf("unsupported helm chart URL scheme for %q, must be http(s):// or oci://", imagePath)
	}
	return spec, nil
}

func helmLogin(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, app *edgeproto.App) error {
	if accessApi == nil {
		return nil
	}
	_, server, auth, err := cloudcommon.GetSecretAuth(ctx, app.ImagePath, app.Key, accessApi, nil)
	if err != nil {
		return err
	}
	if auth == nil {
		return nil
	}
	if strings.HasPrefix(app.ImagePath, "oci://") {
		// use docker login, as helm registry login wasn't working
		log.SpanLog(ctx, log.DebugLevelApi, "docker login for helm registry", "server", server, "username", auth.Username, "app", app.Key)
		cmd := fmt.Sprintf("docker login %s -u %s -p '%s'", server, auth.Username, auth.Password)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("docker login for oci helm chart to server %s failed, %s, %s", server, out, err)
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelApi, "helm registry login", "server", server, "username", auth.Username, "app", app.Key)
		cmd := fmt.Sprintf("helm %s registry login %s -u %s -p '%s'", names.KconfArg, server, auth.Username, auth.Password)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("helm registry login to server %s failed, %s, %s", server, out, err)
		}
	}
	return nil
}

func CreateHelmAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "create kubernetes helm app", "clusterInst", clusterInst, "kubeNames", names)

	// install helm if it's not installed yet
	cmd := fmt.Sprintf("helm %s version", names.KconfArg)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("helm version failed, %s, %s", out, err)
	}

	// get helm repository config for the app
	chartSpec, err := GetHelmChartSpec(app.ImagePath)
	if err != nil {
		return err
	}
	if strings.HasPrefix(chartSpec.URLPath, "http") {
		// Need to add helm repository first
		cmd = fmt.Sprintf("helm %s repo add %s %s", names.KconfArg, chartSpec.RepoName, chartSpec.URLPath)
		out, err = client.Output(cmd)
		if err != nil && strings.Contains(out, "already exists") {
			err = nil
		}
		if err != nil {
			return fmt.Errorf("error adding helm repo, %s, %s, %v", cmd, out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "added helm repository", "app name", app.Key.Name)
		// update repo
		cmd = fmt.Sprintf("helm %s repo update %s", names.KconfArg, chartSpec.RepoName)
		out, err = client.Output(cmd)
		if err != nil {
			return fmt.Errorf("updating helm repo, %s, %s, %v", cmd, out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "helm repo updated", "app name", app.Key.Name)
	}
	nsArgs := getHelmNamespaceArgs(names.InstanceNamespace, cloudcommon.Create)
	helmArgs, err := getHelmInstallOptsString(app.Annotations)
	if err != nil {
		return err
	}
	configs := append(app.Configs, appInst.Configs...)
	helmOpts, err := getHelmOpts(ctx, client, names.AppName, app.TemplateDelimiter, configs)
	if err != nil {
		return err
	}
	err = helmLogin(ctx, accessApi, client, names, app)
	if err != nil {
		return err
	}
	cmd = fmt.Sprintf("helm %s install %s %s %s %s %s", names.KconfArg, names.HelmAppName, chartSpec.ChartRef,
		helmArgs, helmOpts, nsArgs)
	log.SpanLog(ctx, log.DebugLevelInfra, "helm install", "cmd", cmd)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying helm chart, %s, %s, %v", cmd, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "applied helm chart", "app name", app.Key.Name)
	return nil
}

func UpdateHelmAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	nsArgs := getHelmNamespaceArgs(names.InstanceNamespace, cloudcommon.Update)
	log.SpanLog(ctx, log.DebugLevelInfra, "update kubernetes helm app", "app", app, "kubeNames", names)
	helmArgs, err := getHelmInstallOptsString(app.Annotations)
	if err != nil {
		return err
	}
	configs := append(app.Configs, appInst.Configs...)
	helmOpts, err := getHelmOpts(ctx, client, names.AppName, app.TemplateDelimiter, configs)
	if err != nil {
		return err
	}

	// get helm repository config for the app
	// NOTE: since upgrading, no need to add the repo, should already exist
	chartSpec, err := GetHelmChartSpec(app.ImagePath)
	if err != nil {
		return err
	}

	if strings.HasPrefix(chartSpec.URLPath, "http") {
		// Update repos, just in case we need to refresh available versions
		cmd := fmt.Sprintf("helm %s repo update", names.KconfArg)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("updating helm repos, %s, %s, %v", cmd, out, err)
		}
	}
	err = helmLogin(ctx, accessApi, client, names, app)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("helm %s upgrade %s %s %s %s %s", names.KconfArg, nsArgs, helmArgs, helmOpts, names.HelmAppName, chartSpec.ChartRef)
	log.SpanLog(ctx, log.DebugLevelInfra, "Helm options", "helmOpts", helmOpts, "helmArgs", helmArgs, "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error updating helm chart, %s, %s, %v", cmd, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "updated helm chart")
	return nil
}

func DeleteHelmAppInst(ctx context.Context, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst) error {
	nsArgs := getHelmNamespaceArgs(names.InstanceNamespace, cloudcommon.Delete)
	cmd := fmt.Sprintf("helm %s delete %s %s", names.KconfArg, nsArgs, names.HelmAppName)
	log.SpanLog(ctx, log.DebugLevelInfra, "delete kubernetes helm app", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "not found") {
			return fmt.Errorf("error deleting helm chart, %s, %s, %v", cmd, out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Unable to find the chart, continue", "cmd", cmd,
			"out", out, "err", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "removed helm chart")
	err = CleanupHelmConfigs(ctx, client, names.AppName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to cleanup helm app configs", "appname", names.AppName, "err", err)
	}
	return nil
}

// concatenate files with a ',' and prepend '-f'
// Example: ["foo.yaml", "bar.yaml", "foobar.yaml"] ---> "-f foo.yaml,bar.yaml,foobar.yaml"
func getHelmYamlOpt(ymls []string) string {
	// empty string
	if len(ymls) == 0 {
		return ""
	}
	return "-f " + strings.Join(ymls, ",")
}

func CleanupHelmConfigs(ctx context.Context, client ssh.Client, appName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "cleanup kubernetes helm app configs", "appname", appName)
	// count 10 is just for safeguard
	for count := 0; count < 10; count++ {
		fileName := fmt.Sprintf("%s%d", appName, count)
		out, err := client.Output("rm " + fileName)
		if err != nil {
			if strings.Contains(out, "No such file or directory") {
				return nil
			}
			return fmt.Errorf("failed to delete helm config file %s, %s: %v", fileName, out, err)
		}
	}
	return nil
}
