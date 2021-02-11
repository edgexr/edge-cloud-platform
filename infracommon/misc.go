package infracommon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	ssh "github.com/mobiledgex/golang-ssh"
)

var DefaultConnectTimeout time.Duration = 30 * time.Second
var ClientVersion = "SSH-2.0-mobiledgex-ssh-client-1.0"

var SSHOpts = []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "LogLevel=ERROR"}
var SSHUser = "ubuntu"

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

func SeedDockerSecret(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst, imagePath string, accessApi platform.AccessApi) error {
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
	auth, err := accessApi.GetRegistryAuth(ctx, imagePath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot get docker registry secret from vault - assume public registry", "err", err)
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

	cmd = fmt.Sprintf("cat .docker-pass | docker login -u %s --password-stdin %s ", auth.Username, auth.Hostname)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't docker login on rootlb to %s, %s, %v", auth.Hostname, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "docker login ok")
	return nil
}

func WriteTemplateFile(filename string, buf *bytes.Buffer) error {
	outFile, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to write heat template %s: %s", filename, err.Error())
	}
	_, err = outFile.WriteString(buf.String())

	if err != nil {
		outFile.Close()
		os.Remove(filename)
		return fmt.Errorf("unable to write heat template file %s: %s", filename, err.Error())
	}
	outFile.Sync()
	outFile.Close()
	return nil
}

func IncrIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type ErrorResp struct {
	Error  string   `json:"error,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

// for reading errors from an http response
func GetReqErr(reqBody io.ReadCloser) error {
	body, err := ioutil.ReadAll(reqBody)
	if err != nil {
		return err
	}
	errorResp := ErrorResp{}
	err = json.Unmarshal(body, &errorResp)
	if err != nil {
		// string error
		return fmt.Errorf("%s", body)
	}
	combineErrors(&errorResp)
	return fmt.Errorf("Errors: %s", strings.Join(errorResp.Errors, ","))
}

func combineErrors(e *ErrorResp) {
	e.Errors = append(e.Errors, e.Error)
}

// round the given field denoted by digIdx, we mostly want seconds
// rounded to two digits
func FormatDuration(dur time.Duration, digIdx int) string {

	var divisors = []time.Duration{
		time.Duration(1),
		time.Duration(10),
		time.Duration(100),
		time.Duration(1000),
	}
	switch {
	case dur > time.Second:
		dur = dur.Round(time.Second / divisors[digIdx])
	case dur > time.Millisecond:
		dur = dur.Round(time.Millisecond / divisors[digIdx])
	case dur > time.Microsecond:
		dur = dur.Round(time.Millisecond / divisors[digIdx])
	}
	return dur.String()
}
