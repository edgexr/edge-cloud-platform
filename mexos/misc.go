package mexos

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

func PrivateSSHKey() string {
	return MEXDir() + "/id_rsa_mex"
}

func MEXDir() string {
	return os.Getenv("HOME") + "/.mobiledgex"
}

func DefaultKubeconfig() string {
	return os.Getenv("HOME") + "/.kube/config"
}

func CopyFile(src string, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(dst, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func SeedDockerSecret(ctx context.Context, plat platform.Platform, client ssh.Client, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, vaultConfig *vault.Config) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "seed docker secret", "imagepath", app.ImagePath)

	urlObj, err := util.ImagePathParse(app.ImagePath)
	if err != nil {
		return fmt.Errorf("Cannot parse image path: %s - %v", app.ImagePath, err)
	}
	if urlObj.Host == cloudcommon.DockerHub {
		log.SpanLog(ctx, log.DebugLevelMexos, "no secret needed for public image")
		return nil
	}
	auth, err := cloudcommon.GetRegistryAuth(ctx, app.ImagePath, vaultConfig)
	if err != nil {
		return err
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
	log.SpanLog(ctx, log.DebugLevelMexos, "stored docker password")
	defer func() {
		cmd := fmt.Sprintf("rm .docker-pass")
		out, err = client.Output(cmd)
	}()

	cmd = fmt.Sprintf("cat .docker-pass | docker login -u %s --password-stdin %s ", auth.Username, auth.Hostname)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't docker login on rootlb to %s, %s, %v", auth.Hostname, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "docker login ok")
	return nil
}
