package mexos

import (
	"encoding/json"
	"fmt"
	"strings"

	valid "github.com/asaskevich/govalidator"
	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/log"
)

func runLocalMexAgent() error {
	os, err := GetLocalOperatingSystem()
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "runLocalMexAgent", "os", os)

	// It is currently assumed that Mac will run this as just a local process and linux will run as a service.  Mac env
	// are for dev-test only, and Linux is for actual deployments.   This assumption
	// could change in future, in which case we will need another setting to determine how to run the process.  Also, we should
	// eventually be running this as a container in either case which will change this.
	switch os {
	case cloudcommon.OperatingSystemMac:
		var localMexos process.MexAgentLocal
		return localMexos.Start("/tmp/mexosagent.log")
	case cloudcommon.OperatingSystemLinux:
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

//RunMEXAgent runs the MEX agent on the RootLB. It first registers FQDN to cloudflare domain registry if not already registered.
//   It then obtains certficiates from Letsencrypt, if not done yet.  Then it runs the docker instance of MEX agent
//   on the RootLB. It can be told to manually pull image from docker repository.  This allows upgrading with new image.
//   It uses MEX private docker repository.  If an instance is running already, we don't start another one.
func RunMEXAgent(rootLBName string, cloudletKey *edgeproto.CloudletKey) error {
	log.DebugLog(log.DebugLevelMexos, "run mex agent")

	if CloudletIsDIND() {
		if err := runLocalMexAgent(); err != nil {
			log.DebugLog(log.DebugLevelMexos, "error in runLocalMexAgent", "err", err)
		}
		if GetCloudletNetworkScheme() == cloudcommon.NetworkSchemePublicIP {
			if err := ActivateFQDNA(rootLBName); err != nil {
				log.DebugLog(log.DebugLevelMexos, "error in ActivateFQDNA", "err", err)
				return err
			}
		}
		log.DebugLog(log.DebugLevelMexos, "done setup mexosagent for  dind")
		return nil
	}
	if CloudletIsPublicCloud() {
		log.DebugLog(log.DebugLevelMexos, "skip mex agent for public cloud") //TODO: maybe later we will actually have agent on public cloud
		return nil
	}
	fqdn := rootLBName
	//fqdn is that of the machine/kvm-instance running the agent
	if !valid.IsDNSName(fqdn) {
		return fmt.Errorf("fqdn %s is not valid", fqdn)
	}
	sd, err := GetServerDetails(fqdn)
	if err == nil {
		if sd.Name == fqdn {
			log.DebugLog(log.DebugLevelMexos, "server with same name as rootLB exists", "fqdn", fqdn)
			rootLB, err := getRootLB(fqdn)
			if err != nil {
				return fmt.Errorf("cannot find rootlb %s", fqdn)
			}
			extIP, err := GetServerIPAddr(GetCloudletExternalNetwork(), fqdn)
			if err != nil {
				return fmt.Errorf("cannot get rootLB IP %sv", err)
			}
			log.DebugLog(log.DebugLevelMexos, "set rootLB IP to", "ip", extIP)
			rootLB.IP = extIP
			// now ensure the rootLB can reach all the internal networks
			err = LBAddRouteAndSecRules(rootLB.Name)
			if err != nil {
				return fmt.Errorf("failed to LBAddRouteAndSecRules %v", err)
			}
			//return RunMEXOSAgentContainer(rootLB)
			return RunMEXOSAgentService(rootLB.Name)
		}
	}
	log.DebugLog(log.DebugLevelMexos, "about to create mex agent", "fqdn", fqdn)
	rootLB, err := getRootLB(fqdn)
	if err != nil {
		return fmt.Errorf("cannot find rootlb %s", fqdn)
	}
	if rootLB == nil {
		return fmt.Errorf("cannot run mex agent manifest, rootLB is null")
	}
	if GetCloudletOSImage() == "" {
		return fmt.Errorf("missing agent image")
	}
	log.DebugLog(log.DebugLevelMexos, "record platform config")
	err = EnableRootLB(rootLB, cloudletKey)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "can't enable agent", "name", rootLB.Name)
		return fmt.Errorf("Failed to enable root LB %v", err)
	}
	extIP, err := GetServerIPAddr(GetCloudletExternalNetwork(), fqdn)
	if err != nil {
		return fmt.Errorf("cannot get rootLB IP %sv", err)
	}
	log.DebugLog(log.DebugLevelMexos, "set rootLB IP to", "ip", extIP)
	rootLB.IP = extIP

	err = WaitForRootLB(rootLB)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "timeout waiting for agent to run", "name", rootLB.Name)
		return fmt.Errorf("Error waiting for rootLB %v", err)
	}
	if err := SetupSSHUser(rootLB, sshUser); err != nil {
		return err
	}
	if err = ActivateFQDNA(rootLB.Name); err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "FQDN A record activated", "name", rootLB.Name)
	err = AcquireCertificates(rootLB.Name) //fqdn name may be different than rootLB.Name
	if err != nil {
		return fmt.Errorf("can't acquire certificate for %s, %v", rootLB.Name, err)
	}
	log.DebugLog(log.DebugLevelMexos, "acquired certificates from letsencrypt", "name", rootLB.Name)
	err = GetHTPassword(rootLB.Name)
	if err != nil {
		return fmt.Errorf("can't download htpassword %v", err)
	}
	// now ensure the rootLB can reach all the internal networks
	err = LBAddRouteAndSecRules(rootLB.Name)
	if err != nil {
		return fmt.Errorf("failed to LBAddRouteAndSecRules %v", err)
	}
	//return RunMEXOSAgentContainer(mf, rootLB)
	return RunMEXOSAgentService(rootLB.Name)
}

func RunMEXOSAgentService(rootLBName string) error {
	//TODO check if agent is running before restarting again.
	log.DebugLog(log.DebugLevelMexos, "run mexosagent service")
	client, err := getClusterSSHClient(rootLBName)
	if err != nil {
		return err
	}
	for _, act := range []string{"stop", "disable"} {
		out, err := client.Output("sudo systemctl " + act + " mexosagent.service")
		if err != nil {
			log.InfoLog("warning: cannot "+act+" mexosagent.service", "out", out, "err", err)
		}
	}
	log.DebugLog(log.DebugLevelMexos, "copying new mexosagent service")
	//TODO name should come from mf.Values and allow versioning
	// scp the agent from the registry
	for _, dest := range []struct{ path, name string }{
		{"/usr/local/bin", "mexosagent"},
		{"/lib/systemd/system", "mexosagent.service"},
	} {
		cmd := fmt.Sprintf("sudo scp -o %s -o %s -i id_rsa_mex mobiledgex@%s:files-repo/mobiledgex/%s %s", sshOpts[0], sshOpts[1], GetCloudletRegistryFileServer(), dest.name, dest.path)
		out, err := client.Output(cmd)
		if err != nil {
			log.InfoLog("error: cannot download from registry", "fn", dest.name, "path", dest.path, "error", err, "out", out)
			return err
		}
		out, err = client.Output(fmt.Sprintf("sudo chmod a+rx %s/%s", dest.path, dest.name))
		if err != nil {
			log.InfoLog("error: cannot chmod", "error", err, "fn", dest.name, "path", dest.path)
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

func RunMEXOSAgentContainer(rootLB *MEXRootLB) error {
	client, err := GetSSHClient(rootLB.Name, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return err
	}
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

//RunMEXAgentCloudletKey calls MEXPlatformInit with templated manifest
func RunMEXAgentCloudletKey(rootLBName string, cloudletKeyStr string) error {

	clk := edgeproto.CloudletKey{}
	err := json.Unmarshal([]byte(cloudletKeyStr), &clk)
	if err != nil {
		return fmt.Errorf("can't unmarshal json cloudletkey %s, %v", cloudletKeyStr, err)
	}
	log.DebugLog(log.DebugLevelMexos, "unmarshalled cloudletkeystr", "cloudletkey", clk)
	if clk.Name == "" || clk.OperatorKey.Name == "" {
		return fmt.Errorf("invalid cloudletkeystr %s", cloudletKeyStr)
	}
	return RunMEXAgent(rootLBName, &clk)
}
