package mexos

import (
	"fmt"
	"runtime"
	"strings"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/log"
)

func startLocalMexAgent(logfile string) error {
	var err error
	args := []string{"--debug", "--proxy", ""}
	var envs []string

	_, err = process.StartLocal("mexosagent", "mexosagent", args, envs, logfile)
	return err
}

func RunLocalMexAgent() error {
	os := runtime.GOOS
	log.DebugLog(log.DebugLevelMexos, "runLocalMexAgent", "os", os)

	// It is currently assumed that Mac will run this as just a local process and linux will run as a service.  Mac env
	// are for dev-test only, and Linux is for actual deployments.   This assumption
	// could change in future, in which case we will need another setting to determine how to run the process.  Also, we should
	// eventually be running this as a container in either case which will change this.
	switch os {
	case "darwin":
		return startLocalMexAgent("/tmp/mexosagent.log")
	case "linux":
		out, err := sh.Command("sudo", "service", "mexosagent", "start").CombinedOutput()
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error in mexosagent start", "out", string(out), "err", err)
			return err
		}
		out, err = sh.Command("sudo", "systemctl", "enable", "mexosagent").CombinedOutput()
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error in mexosagent enable", "out", string(out), "err", err)
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS: %s", os)
	}
}

func getMexosAgentRemoteFilename() string {
	return "mexosagent-" + MEXInfraVersion
}

func getMexosAgentServiceRemoteFilename() string {
	return "mexosagent.service-" + MEXInfraVersion
}

func RunMEXOSAgentService(client pc.PlatformClient) error {
	//TODO check if agent is running before restarting again.
	log.DebugLog(log.DebugLevelMexos, "run mexosagent service")

	for _, act := range []string{"stop", "disable"} {
		out, err := client.Output("sudo systemctl " + act + " mexosagent.service")
		if err != nil {
			log.InfoLog("warning: cannot "+act+" mexosagent.service", "out", out, "err", err)
		}
	}
	log.DebugLog(log.DebugLevelMexos, "copying new mexosagent service")
	//TODO name should come from mf.Values and allow versioning
	// scp the agent from the registry
	for _, dest := range []struct{ path, remotename, localname string }{
		{"/usr/local/bin", getMexosAgentRemoteFilename(), "mexosagent"},
		{"/lib/systemd/system", getMexosAgentServiceRemoteFilename(), "mexosagent.service"},
	} {
		cmd := fmt.Sprintf("sudo scp -C -o %s -o %s -i id_rsa_mex mobiledgex@%s:files-repo/mobiledgex/%s %s/%s", sshOpts[0], sshOpts[1], GetCloudletRegistryFileServer(), dest.remotename, dest.path, dest.localname)
		out, err := client.Output(cmd)
		if err != nil {
			log.InfoLog("error: cannot download from registry", "remotefile", dest.remotename, "path", dest.path, "localfile", dest.localname, "error", err, "out", out)
			return err
		}
		out, err = client.Output(fmt.Sprintf("sudo chmod a+rx %s/%s", dest.path, dest.localname))
		if err != nil {
			log.InfoLog("error: cannot chmod", "error", err, "fn", dest.localname, "path", dest.path)
			return err
		}
	}

	log.DebugLog(log.DebugLevelMexos, "starting mexosagent.service")
	for _, act := range []string{"enable", "start"} {
		out, err := client.Output("sudo systemctl " + act + " mexosagent.service")
		if err != nil {
			log.InfoLog("warning: cannot "+act+" mexosagent.service", "out", out, "err", err)
		}
	}
	log.DebugLog(log.DebugLevelMexos, "started mexosagent.service")
	return nil
}

// XXX This function isn't called anymore - can it be deleted?
func RunMEXOSAgentContainer(client pc.PlatformClient, rootLB *MEXRootLB) error {
	//XXX rewrite this with --format {{.Names}}
	cmd := fmt.Sprintf("docker ps --filter ancestor=%s --format {{.Names}}", GetCloudletAgentContainerImage())
	out, err := client.Output(cmd)
	if err == nil && strings.Contains(out, rootLB.Name) {
		//agent docker instance exists
		//XXX check better
		log.DebugLog(log.DebugLevelMexos, "agent docker instance already running")
		return nil
	}
	cmd = fmt.Sprintf("echo %s > .docker-pass", GetCloudletDockerPass())
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't store docker pass, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "seeded docker registry password")
	dockerinstanceName := fmt.Sprintf("%s-%s", "mexos", rootLB.Name)

	cmd = fmt.Sprintf("cat .docker-pass| docker login -u mobiledgex --password-stdin %s", GetCloudletDockerRegistry())
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error docker login at %s, %s, %s, %v", rootLB.Name, cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "docker login ok")
	cmd = fmt.Sprintf("docker pull %s", GetCloudletAgentContainerImage()) //probably redundant
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error pulling docker image at %s, %s, %s, %v", rootLB.Name, cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "pulled agent image ok")
	cmd = fmt.Sprintf("docker run -d --rm --name %s --net=host -v `pwd`:/var/www/.cache -v /etc/ssl/certs:/etc/ssl/certs %s -debug", dockerinstanceName, GetCloudletAgentContainerImage())
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error running dockerized agent on RootLB %s, %s, %s, %v", rootLB.Name, cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "now running dockerized mexosagent")
	return nil
}
