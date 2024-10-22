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

package dockermgmt

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/kballard/go-shellquote"
	yaml "github.com/mobiledgex/yaml/v2"
)

var createZip = "createZip"
var deleteZip = "deleteZip"

var UseInternalPortInContainer = "internalPort"
var UsePublicPortInContainer = "publicPort"

type DockerNetworkingMode string

var DockerHostMode DockerNetworkingMode = "hostMode"
var DockerBridgeMode DockerNetworkingMode = "bridgeMode"

type DockerOptions struct {
	ForceImagePull  bool
	ExposePorts     bool
	NoHostNetwork   bool
	StopTimeoutSecs int
}

type DockerReqOp func(do *DockerOptions) error

func WithForceImagePull(force bool) DockerReqOp {
	return func(d *DockerOptions) error {
		d.ForceImagePull = force
		return nil
	}
}

func WithExposePorts() DockerReqOp {
	return func(d *DockerOptions) error {
		d.ExposePorts = true
		return nil
	}
}

func WithNoHostNetwork() DockerReqOp {
	return func(d *DockerOptions) error {
		d.NoHostNetwork = true
		return nil
	}
}

func WithStopTimeoutSecs(timeoutSecs int) DockerReqOp {
	return func(d *DockerOptions) error {
		d.StopTimeoutSecs = timeoutSecs
		return nil
	}
}

var EnvoyProxy = "envoy"
var NginxProxy = "nginx"

func GetContainerName(appInst *edgeproto.AppInst) string {
	if appInst.CompatibilityVersion >= cloudcommon.AppInstCompatibilityRegionScopeName {
		return util.DNSSanitize(appInst.Key.Name)
	} else if appInst.CompatibilityVersion >= cloudcommon.AppInstCompatibilityUniqueNameKey {
		appInstName := cloudcommon.GetAppInstCloudletScopedName(appInst)
		return util.DNSSanitize(appInstName)
	} else {
		return util.DNSSanitize(appInst.AppKey.Name + appInst.AppKey.Version)
	}
}

// Helper function that generates the ports string for docker command
// Example : "-p 80:80/http -p 7777:7777/tcp"
func GetDockerPortString(ports []dme.AppPort, containerPortType string, proxyMatch, listenIP, listenIPV6 string) []string {
	var cmdArgs []string
	// ensure envoy and nginx docker commands are only opening the udp ports they are managing, not all of the apps udp ports
	for _, p := range ports {
		if p.Proto == dme.LProto_L_PROTO_UDP {
			if proxyMatch == EnvoyProxy && p.Nginx {
				continue
			} else if proxyMatch == NginxProxy && !p.Nginx {
				continue
			}
		}
		proto, err := edgeproto.LProtoStr(p.Proto)
		if err != nil {
			continue
		}
		publicPortStr := fmt.Sprintf("%d", p.PublicPort)
		if p.EndPort != 0 && p.EndPort != p.PublicPort {
			publicPortStr = fmt.Sprintf("%d-%d", p.PublicPort, p.EndPort)
		}
		containerPort := p.PublicPort
		if containerPortType == UseInternalPortInContainer {
			containerPort = p.InternalPort
		}
		containerPortStr := fmt.Sprintf("%d", containerPort)
		if p.EndPort != 0 && p.EndPort != containerPort {
			containerPortStr = fmt.Sprintf("%d-%d", containerPort, p.EndPort)
		}
		var listenIPs []string
		// special case for listening on all interfaces
		if (listenIP == "" || listenIP == "0.0.0.0") && (listenIPV6 == "" || listenIPV6 == "::") {
			listenIPs = []string{""}
		} else {
			listenIPs = []string{
				listenIP + ":",
				listenIPV6 + ":",
			}
		}
		for _, listenIPStr := range listenIPs {
			pstr := fmt.Sprintf("%s%s:%s/%s", listenIPStr, publicPortStr, containerPortStr, proto)
			cmdArgs = append(cmdArgs, "-p", pstr)
		}
	}
	return cmdArgs
}

func getDockerComposeFileName(app *edgeproto.App, appInst *edgeproto.AppInst) string {
	if appInst.CompatibilityVersion >= cloudcommon.AppInstCompatibilityUniqueNameKey {
		return util.DNSSanitize("docker-compose-"+appInst.Key.Name) + ".yml"
	} else if appInst.CompatibilityVersion >= cloudcommon.AppInstCompatibilityUniqueNameKey {
		appInstName := cloudcommon.GetAppInstCloudletScopedName(appInst)
		return util.DNSSanitize("docker-compose-"+appInstName) + ".yml"
	} else {
		return util.DNSSanitize("docker-compose-"+app.Key.Name+app.Key.Version) + ".yml"
	}
}

func getDockerComposeEnvFileName(appInst *edgeproto.AppInst) string {
	return util.DNSSanitize("docker-compose-"+appInst.Key.Name) + ".env"
}

func parseDockerComposeManifest(client ssh.Client, dir string, dm *cloudcommon.DockerManifest) error {
	cmd := fmt.Sprintf("cat %s/%s", dir, "manifest.yml")
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error cat manifest, %s, %v", out, err)
	}
	err = yaml.Unmarshal([]byte(out), &dm)
	if err != nil {
		return fmt.Errorf("unmarshalling manifest.yml: %v", err)
	}
	return nil
}

func handleDockerZipfile(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, app *edgeproto.App, appInst *edgeproto.AppInst, action string, envFileArg string, opts ...DockerReqOp) error {
	var dockerOpt DockerOptions
	for _, op := range opts {
		if err := op(&dockerOpt); err != nil {
			return err
		}
	}
	dir := util.DockerSanitize(app.Key.Name + app.Key.Organization + app.Key.Version)
	log.SpanLog(ctx, log.DebugLevelInfra, "handle docker zip file", "dir", dir, "url", app.DeploymentManifest, "action", action)
	var dockerComposeCommand string

	if action == createZip {
		dockerComposeCommand = "up -d"

		// create a directory for the app and its files
		err := pc.CreateDir(ctx, client, dir, pc.Overwrite, pc.NoSudo)
		if err != nil {
			return err
		}
		passParams := ""
		auth, err := accessApi.GetRegistryAuth(ctx, app.DeploymentManifest)
		if err != nil {
			return err
		}
		if auth != nil {
			switch auth.AuthType {
			case cloudcommon.BasicAuth:
				passParams = fmt.Sprintf("--user %s --password %s", auth.Username, auth.Password)
			case cloudcommon.ApiKeyAuth:
				passParams = fmt.Sprintf(`--header="X-JFrog-Art-Api: %s"`, auth.ApiKey)
			case cloudcommon.TokenAuth:
				passParams = fmt.Sprintf(`--header="Authorization: Bearer %s"`, auth.Token)
			case cloudcommon.NoAuth:
			default:
				log.SpanLog(ctx, log.DebugLevelApi, "warning, cannot get registry credentials from vault - unknown authtype", "authType", auth.AuthType)
			}
		}
		// pull the zipfile
		cmd := fmt.Sprintf("wget %s -T 60 -P %s %s", passParams, dir, app.DeploymentManifest)
		out, err := client.Output(cmd)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "wget err", "cmd", cmd, "out", out, "err", err)
			return fmt.Errorf("wget of app zipfile failed: %s %v", out, err)
		}
		s := strings.Split(app.DeploymentManifest, "/")
		zipfile := s[len(s)-1]
		cmd = "unzip -o -d " + dir + " " + dir + "/" + zipfile
		log.SpanLog(ctx, log.DebugLevelInfra, "running unzip", "cmd", cmd)
		out, err = client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error unzipping, %s, %v", out, err)
		}
		// find the files which were extracted
		cmd = "ls -m " + dir
		out, err = client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error running ls, %s, %v", out, err)
		}

		manifestFound := false
		files := strings.Split(out, ",")

		for _, f := range files {

			f = strings.TrimSpace(f)
			log.SpanLog(ctx, log.DebugLevelInfra, "found file", "file", f)
			if f == "manifest.yml" {
				manifestFound = true
			}
		}
		if !manifestFound {
			return fmt.Errorf("no manifest.yml file found in zipfile")
		}
	} else {
		// delete
		dockerComposeCommand = "down"
	}
	// parse the yaml manifest and find the compose files
	var dm cloudcommon.DockerManifest
	err := parseDockerComposeManifest(client, dir, &dm)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error in parsing docker manifest", "dir", dir, "err", err)
		// for create this is fatal, for delete keep going and cleanup what we can
		if action == createZip {
			return err
		}
	}
	if len(dm.DockerComposeFiles) == 0 && action == createZip {
		return fmt.Errorf("no docker compose files in manifest: %v", err)
	}
	for _, d := range dm.DockerComposeFiles {
		if action == createZip && dockerOpt.ForceImagePull {
			log.SpanLog(ctx, log.DebugLevelInfra, "forcing image pull", "file", d)
			pullcmd := fmt.Sprintf("docker-compose -f %s/%s %s", dir, d, "pull")
			out, err := client.Output(pullcmd)
			if err != nil {
				return fmt.Errorf("error pulling image for docker-compose file: %s, %s, %v", d, out, err)
			}
		}

		cmd := fmt.Sprintf("docker-compose%s -f %s/%s %s", envFileArg, dir, d, dockerComposeCommand)
		log.SpanLog(ctx, log.DebugLevelInfra, "running docker-compose", "cmd", cmd)
		out, err := client.Output(cmd)

		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error running docker compose", "out", out, "err", err)
			// for create this is fatal, for delete keep going and cleanup what we can
			if action == createZip {
				return fmt.Errorf("error running docker compose, %s, %v", out, err)
			}
		}
	}

	//cleanup the directory on delete
	if action == deleteZip {
		log.SpanLog(ctx, log.DebugLevelInfra, "deleting app dir", "dir", dir)
		err := pc.DeleteDir(ctx, client, dir, pc.SudoOn)
		if err != nil {
			return fmt.Errorf("error deleting dir, %v", err)
		}
	}
	return nil

}

// createDockerComposeFile creates a docker compose file and returns the file name
func createDockerComposeFile(ctx context.Context, client ssh.Client, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	filename := getDockerComposeFileName(app, appInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "creating docker compose file", "filename", filename)

	err := pc.WriteFile(client, filename, app.DeploymentManifest, "Docker compose file", pc.NoSudo)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Error writing docker compose file", "err", err)
		return "", err
	}
	return filename, nil
}

func getLabelsStr(appInst *edgeproto.AppInst) string {
	labels := cloudcommon.GetAppInstLabels(appInst)
	labelsStr := ""
	for k, v := range labels.Map() {
		labelsStr += fmt.Sprintf(" -l %s=%s", k, v)
	}
	return labelsStr
}

// Local Docker AppInst create is different due to fact that MacOS doesn't like '--network=host' option.
// Instead on MacOS docker needs to have port mapping  explicity specified with '-p' option.
// As a result we have a separate function specifically for a docker app creation on a MacOS laptop
// TODO: Replace this with CreateAppInst with WithExportPorts() and WithNoHostNetwork() options.
func CreateAppInstLocal(ctx context.Context, client ssh.Client, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	image := app.ImagePath
	name := GetContainerName(appInst)
	cluster := util.DockerSanitize(appInst.ClusterKey.Organization + "-" + appInst.ClusterKey.Name)
	baseCmd := "docker run "
	if cloudcommon.AppInstGpuCount(appInst) > 0 {
		baseCmd += "--gpus all"
	}
	labelsStr := getLabelsStr(appInst)
	if app.DeploymentManifest == "" {
		cmd := fmt.Sprintf("%s -d -l edge-cloud -l cluster=%s %s --restart=unless-stopped --name=%s %s %s %s", baseCmd,
			cluster, labelsStr, name,
			strings.Join(GetDockerPortString(appInst.MappedPorts, UseInternalPortInContainer, "", cloudcommon.IPAddrAllInterfaces, cloudcommon.IPV6AddrAllInterfaces), " "), image, getCommandString(app))
		log.SpanLog(ctx, log.DebugLevelInfra, "running docker run ", "cmd", cmd)

		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error running app, %s, %v", out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "done docker run ")
	} else {
		filename, err := createDockerComposeFile(ctx, client, app, appInst)
		if err != nil {
			return err
		}
		// TODO - missing a label for the metaAppInst label.
		// There is a feature request in docker for it - https://github.com/docker/compose/issues/6159
		// Once that's merged we can add label here too
		// cmd := fmt.Sprintf("docker-compose -f %s -l %s=%s up -d", filename, cloudcommon.MexAppInstanceLabel, labelVal)
		cmd := fmt.Sprintf("docker-compose -f %s up -d", filename)
		log.SpanLog(ctx, log.DebugLevelInfra, "running docker-compose", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error running docker compose up, %s, %v", out, err)
		}
	}
	return nil
}

func getCommandString(app *edgeproto.App) string {
	// Make sure to quote user input run on the command line
	// to avoid command injection attacks
	args := append([]string{app.Command}, app.CommandArgs...)
	safeArgs := []string{}
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if str, err := strconv.Unquote(arg); err == nil {
			arg = strings.TrimSpace(str)
		}
		if arg == "" {
			continue
		}
		arg = strconv.Quote(arg)
		safeArgs = append(safeArgs, arg)
	}
	return strings.Join(safeArgs, " ")
}

func CreateAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, app *edgeproto.App, appInst *edgeproto.AppInst, opts ...DockerReqOp) error {
	var dockerOpt DockerOptions
	for _, op := range opts {
		if err := op(&dockerOpt); err != nil {
			return err
		}
	}
	image := app.ImagePath
	labelsStr := getLabelsStr(appInst)
	baseCmd := "docker run "
	if cloudcommon.AppInstGpuCount(appInst) > 0 {
		baseCmd += "--gpus all"
	}
	if dockerOpt.ExposePorts {
		baseCmd += " " + strings.Join(GetDockerPortString(appInst.MappedPorts, UseInternalPortInContainer, "", cloudcommon.IPAddrAllInterfaces, cloudcommon.IPV6AddrAllInterfaces), " ")
	}
	if !dockerOpt.NoHostNetwork {
		baseCmd += " --network=host"
	}

	envFileArg := ""
	if len(app.EnvVars) > 0 || len(app.SecretEnvVars) > 0 {
		envFile := getDockerComposeEnvFileName(appInst)
		secretVars, err := accessApi.GetAppSecretVars(ctx, &app.Key)
		if err != nil {
			return err
		}
		if len(secretVars) != len(app.SecretEnvVars) {
			return fmt.Errorf("failed to get the correct number of App secret vars from encrypted storage, expected %d but only got %d", len(app.SecretEnvVars), len(secretVars))
		}
		buf := bytes.Buffer{}
		for k, v := range app.EnvVars {
			buf.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		}
		for k, v := range secretVars {
			buf.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		}
		err = pc.WriteFile(client, envFile, buf.String(), "envFile", pc.NoSudo)
		if err != nil {
			return err
		}
		envFileArg = " --env-file " + envFile
	}

	if app.DeploymentManifest == "" {
		if dockerOpt.ForceImagePull {
			log.SpanLog(ctx, log.DebugLevelInfra, "forcing image pull", "image", image)
			pullcmd := "docker image pull " + image
			out, err := client.Output(pullcmd)
			if err != nil {
				return fmt.Errorf("error pulling docker image: %s, %s, %v", image, out, err)
			}
		}
		cmd := fmt.Sprintf("%s%s -d %s --restart=unless-stopped --name=%s %s", baseCmd, envFileArg, labelsStr, GetContainerName(appInst), image)
		cmdArgs, err := shellquote.Split(cmd)
		if err != nil {
			return err
		}
		appCmd := strings.TrimSpace(app.Command)
		if appCmd != "" {
			cmdArgs = append(cmdArgs, appCmd)
		}
		for _, arg := range app.CommandArgs {
			arg = strings.TrimSpace(arg)
			if arg != "" {
				cmdArgs = append(cmdArgs, arg)
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "running docker run", "cmd", cmdArgs)
		out, err := pc.RunSafeOutput(client, cmdArgs[0], cmdArgs[1:])
		if err != nil {
			return fmt.Errorf("error running docker run, %s, %v", out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "done docker run ")
	} else {
		if strings.HasSuffix(app.DeploymentManifest, ".zip") {
			return handleDockerZipfile(ctx, accessApi, client, app, appInst, createZip, envFileArg, opts...)
		}
		filename, err := createDockerComposeFile(ctx, client, app, appInst)
		if err != nil {
			return err
		}
		if dockerOpt.ForceImagePull {
			log.SpanLog(ctx, log.DebugLevelInfra, "forcing image pull", "filename", filename)
			pullcmd := fmt.Sprintf("docker-compose -f %s pull", filename)
			out, err := client.Output(pullcmd)
			if err != nil {
				return fmt.Errorf("error pulling image for docker-compose file: %s, %s, %v", filename, out, err)
			}
		}
		// TODO - missing a label for the metaAppInst label.
		// There is a feature request in docker for it - https://github.com/docker/compose/issues/6159
		// Once that's merged we can add label here too
		// cmd := fmt.Sprintf("docker-compose -f %s -l %s=%s up -d", filename, cloudcommon.MexAppInstanceLabel, labelVal)
		cmd := fmt.Sprintf("docker-compose%s -f %s up -d", envFileArg, filename)
		log.SpanLog(ctx, log.DebugLevelInfra, "running docker-compose", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error running docker compose up, %s, %v", out, err)
		}
	}
	return nil
}

func DeleteAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, app *edgeproto.App, appInst *edgeproto.AppInst, opts ...DockerReqOp) error {
	var dockerOpt DockerOptions
	for _, op := range opts {
		if err := op(&dockerOpt); err != nil {
			return err
		}
	}

	if len(app.EnvVars) > 0 || len(app.SecretEnvVars) > 0 {
		envFile := getDockerComposeEnvFileName(appInst)
		err := pc.DeleteFile(client, envFile, pc.NoSudo)
		if err != nil {
			return err
		}
	}

	if app.DeploymentManifest == "" {
		name := GetContainerName(appInst)
		cmd := fmt.Sprintf("docker stop %s", name)
		if dockerOpt.StopTimeoutSecs != 0 {
			cmd += fmt.Sprintf(" -t %d", dockerOpt.StopTimeoutSecs)
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "running docker stop ", "cmd", cmd)
		removeContainer := true
		out, err := client.Output(cmd)

		if err != nil {
			if strings.Contains(out, "No such container") {
				log.SpanLog(ctx, log.DebugLevelInfra, "container already removed", "cmd", cmd)
				removeContainer = false
			} else {
				return fmt.Errorf("error stopping docker app, %s, %v", out, err)
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "done docker stop", "out", out, "err", err)

		if removeContainer {
			cmd = fmt.Sprintf("docker rm %s", name)
			log.SpanLog(ctx, log.DebugLevelInfra, "running docker rm ", "cmd", cmd)
			out, err := client.Output(cmd)
			if err != nil {
				return fmt.Errorf("error removing docker app, %s, %v", out, err)
			}
		}
	} else {
		if strings.HasSuffix(app.DeploymentManifest, ".zip") {
			return handleDockerZipfile(ctx, accessApi, client, app, appInst, deleteZip, "")
		}
		filename := getDockerComposeFileName(app, appInst)
		cmd := fmt.Sprintf("docker-compose -f %s down", filename)
		log.SpanLog(ctx, log.DebugLevelInfra, "running docker-compose", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error running docker-compose down", "out", out, "err", err)
		}
		err = pc.DeleteFile(client, filename, pc.NoSudo)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "unable to delete file", "filename", filename, "err", err)
		}
	}

	return nil
}

func UpdateAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateAppInst", "appkey", app.Key, "ImagePath", app.ImagePath)

	err := DeleteAppInst(ctx, accessApi, client, app, appInst)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "DeleteAppInst failed, proceeding with create", "appkey", app.Key, "err", err)
	}
	return CreateAppInst(ctx, accessApi, client, app, appInst, WithForceImagePull(true))
}

func appendContainerIdsFromDockerComposeImages(client ssh.Client, dockerComposeFile string, rt *edgeproto.AppInstRuntime) error {
	cmd := fmt.Sprintf("docker-compose -f %s images", dockerComposeFile)
	log.DebugLog(log.DebugLevelInfra, "running docker-compose", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error running docker compose images, %s, %v", out, err)
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		fs := strings.Fields(line)
		if len(fs) == 6 && fs[0] != "Container" {
			rt.ContainerIds = append(rt.ContainerIds, fs[0])
		}
	}
	return nil
}

func GetAppInstRuntime(ctx context.Context, client ssh.Client, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	rt := &edgeproto.AppInstRuntime{}
	rt.ContainerIds = make([]string, 0)

	// try to get the container names from the runtime environment
	labels := cloudcommon.GetAppInstLabels(appInst)
	filterStr := ""
	for k, v := range labels.Map() {
		// filter on first label
		filterStr += fmt.Sprintf(` --filter "label=%s=%s"`, k, v)
	}
	if filterStr != "" {
		cmd := fmt.Sprintf(`docker ps --format "{{.Names}}" %s`, filterStr)
		out, err := client.Output(cmd)
		if err == nil && len(out) > 0 {
			for _, name := range strings.Split(out, "\n") {
				name = strings.TrimSpace(name)
				rt.ContainerIds = append(rt.ContainerIds, name)
			}
			return rt, nil
		} else {
			log.SpanLog(ctx, log.DebugLevelInfo, "GetAppInstRuntime cmd failed", "cmd", cmd, "out", out, "err", err)
		}
	}

	// get the expected names if couldn't get it from the runtime
	if app.DeploymentManifest == "" {
		//  just one container identified by the appinst uri
		name := GetContainerName(appInst)
		rt.ContainerIds = append(rt.ContainerIds, name)
	} else {
		if strings.HasSuffix(app.DeploymentManifest, ".zip") {

			var dm cloudcommon.DockerManifest
			dir := util.DockerSanitize(app.Key.Name + app.Key.Organization + app.Key.Version)
			err := parseDockerComposeManifest(client, dir, &dm)
			if err != nil {
				return rt, err
			}
			for _, d := range dm.DockerComposeFiles {
				err := appendContainerIdsFromDockerComposeImages(client, dir+"/"+d, rt)
				if err != nil {
					return rt, err
				}
			}
		} else {
			filename := getDockerComposeFileName(app, appInst)
			err := appendContainerIdsFromDockerComposeImages(client, filename, rt)
			if err != nil {
				return rt, err
			}
		}
	}
	return rt, nil
}

func GetContainerCommand(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	// If no container specified, pick the first one in the AppInst.
	// Note that for docker we currently expect just one
	if req.ContainerId == "" {
		if appInst.RuntimeInfo.ContainerIds == nil ||
			len(appInst.RuntimeInfo.ContainerIds) == 0 {
			return "", fmt.Errorf("no containers found for AppInst, please specify one")
		}
		for _, name := range appInst.RuntimeInfo.ContainerIds {
			// prefer non-nginx/envoy container
			if !strings.HasPrefix(name, "nginx") && !strings.HasPrefix(name, "envoy") {
				req.ContainerId = name
				break
			}
		}
		if req.ContainerId == "" {
			req.ContainerId = appInst.RuntimeInfo.ContainerIds[0]
		}
	}
	if req.Cmd != nil {
		cmdStr := fmt.Sprintf("docker exec -it %s %s", req.ContainerId, req.Cmd.Command)
		return cmdStr, nil
	}
	if req.Log != nil {
		cmdStr := "docker logs "
		if req.Log.Since != "" {
			cmdStr += fmt.Sprintf("--since %s ", req.Log.Since)
		}
		if req.Log.Tail != 0 {
			cmdStr += fmt.Sprintf("--tail %d ", req.Log.Tail)
		}
		if req.Log.Timestamps {
			cmdStr += "--timestamps "
		}
		if req.Log.Follow {
			cmdStr += "--follow "
		}
		cmdStr += req.ContainerId
		return cmdStr, nil
	}
	return "", fmt.Errorf("no command or log specified with exec request")
}

// SingleOpts are docker run options that take no option value.
var SingleOpts = map[string]struct{}{
	"-d":                      {},
	"--detach":                {},
	"--disable-content-trust": {},
	"--help":                  {},
	"--init":                  {},
	"-i":                      {},
	"--interactive":           {},
	"--no-healthcheck":        {},
	"--oom-kill-disable":      {},
	"--privileged":            {},
	"-P":                      {},
	"--publish-all":           {},
	"--read-only":             {},
	"--rm":                    {},
	"--sig-proxy":             {},
	"-t":                      {},
	"--tty":                   {},
}

// Attempt to see if running container matches the desired run state from the
// args. On updates, this is used to decide if the container needs to be stopped
// and started to apply new run args.
// Note: ports are not checked because we use host network mode, and so ports are
// never specified.
func ArgsMatchRunning(ctx context.Context, runningData types.ContainerJSON, runArgs []string) bool {
	binds := []string{}
	image := ""
	cmdArgs := []string{}
	network := ""
	for ii := 0; ii < len(runArgs); ii++ {
		arg := runArgs[ii]
		if arg == "" || arg == "docker" || arg == "run" {
			continue
		}
		var opt, optVal string
		if arg[0] == '-' {
			opt = arg
			if parts := strings.Split(arg, "="); len(parts) > 1 {
				opt = parts[0]
				optVal = parts[1]
			} else if _, found := SingleOpts[opt]; !found && ii+1 < len(runArgs) {
				optVal = runArgs[ii+1]
				ii++
			}
		}
		if arg == "-v" {
			binds = append(binds, optVal)
		} else if arg == "--network" {
			network = optVal
		}
		if opt != "" {
			continue
		}
		// image name
		image = arg
		cmdArgs = runArgs[ii+1:]
		break
	}

	runningBinds := []string{}
	if runningData.ContainerJSONBase != nil && runningData.HostConfig != nil && runningData.HostConfig.Binds != nil {
		runningBinds = runningData.ContainerJSONBase.HostConfig.Binds
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "docker args match check binds", "args", binds, "running", runningBinds)
	if len(binds) != len(runningBinds) {
		return false
	}
	for ii, bind := range binds {
		if bind != runningBinds[ii] {
			return false
		}
	}

	runningNetworkMode := ""
	if runningData.ContainerJSONBase != nil && runningData.HostConfig != nil {
		runningNetworkMode = string(runningData.ContainerJSONBase.HostConfig.NetworkMode)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "docker args match check host network mode", "args", network, "running", runningNetworkMode)
	if network == "host" && runningNetworkMode != "host" {
		return false
	}

	runningImage := ""
	if runningData.Config != nil {
		runningImage = runningData.Config.Image
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "docker args match check image", "args", image, "running", runningImage)
	if image != runningImage {
		return false
	}

	runningArgs := []string{}
	if runningData.ContainerJSONBase != nil {
		runningArgs = runningData.ContainerJSONBase.Args
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "docker args match check command args", "args", cmdArgs, "running", runningArgs)
	if len(cmdArgs) != len(runningArgs) {
		return false
	}
	for ii, arg := range cmdArgs {
		if arg != runningData.Args[ii] {
			return false
		}
	}
	return true
}

func DockerImagePresent(ctx context.Context, client ssh.Client, image string) (bool, error) {
	out, err := client.Output("docker image inspect " + image)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "docker image is present", "image", image)
		return true, nil
	}
	if strings.Contains(err.Error(), "No such image") {
		log.SpanLog(ctx, log.DebugLevelInfra, "docker image is not present", "image", image)
		return false, nil
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "check docker image present failed", "image", image, "out", out, "err", err)
	return false, fmt.Errorf("failed to check if image %s present, %s, %s", image, out, err)
}

func SeedDockerSecret(ctx context.Context, client ssh.Client, imagePath string, authAPI cloudcommon.RegistryAuthApi) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "seed docker secret", "imagepath", imagePath)

	if !strings.Contains(imagePath, "/") {
		// docker-compose or zip type apps may have public images with no path which cannot be
		// parsed as a url.  Allow these to proceed without a secret.  They won't have dockerhub as
		// the host because the path is embedded within the compose or zipfile
		log.SpanLog(ctx, log.DebugLevelInfra, "no secret seeded for app without hostname")
		return nil
	}
	urlObj, err := util.ImagePathParse(imagePath)
	if err != nil {
		return fmt.Errorf("Cannot parse image path: %s - %v", imagePath, err)
	}
	if urlObj.Host == cloudcommon.DockerHub {
		log.SpanLog(ctx, log.DebugLevelInfra, "no secret needed for public image")
		return nil
	}
	auth, err := authAPI.GetRegistryAuth(ctx, imagePath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot get docker registry secret from vault - assume public registry", "image", imagePath, "err", err)
		return nil
	}
	if auth.AuthType == cloudcommon.NoAuth {
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, no registry credentials in vault, assume public registry", "image", imagePath)
		return nil
	}
	if auth.AuthType != cloudcommon.BasicAuth {
		return fmt.Errorf("auth type for %s is not basic auth type", auth.Hostname)
	}
	// XXX: not sure writing password to file buys us anything if the
	// echo command is recorded in some history.
	cmd := fmt.Sprintf("echo %s > .docker-pass", auth.Password)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't store docker password, %s, %v", out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "stored docker password")
	defer func() {
		cmd := fmt.Sprintf("rm .docker-pass")
		out, err = client.Output(cmd)
	}()

	// quote username to deal with harbor api users which
	// have a '$' in the name.
	cmd = fmt.Sprintf("cat .docker-pass | docker login -u '%s' --password-stdin %s ", auth.Username, auth.Hostname)
	out, err = client.Output(cmd)
	if err != nil && strings.Contains(err.Error(), "Client.Timeout exceeded") {
		// docker login to harbor on a newly created LB VM seems to fail
		// with a timeout sometimes. retry to avoid spurious errors.
		log.SpanLog(ctx, log.DebugLevelInfra, "docker login failed due to timeout, retrying", "err", err)
		out, err = client.Output(cmd)
	}
	if err != nil {
		return fmt.Errorf("can't docker login on rootlb to %s, %s, %v", auth.Hostname, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "docker login ok")
	return nil
}
