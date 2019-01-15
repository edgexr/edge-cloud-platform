package mexos

import (
	"fmt"
	"strings"

	valid "github.com/asaskevich/govalidator"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/cloudflare"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/log"
)

func runLocalMexAgent() error {
	log.DebugLog(log.DebugLevelMexos, "run local mexosagent")
	var localMexos process.MexAgentLocal
	return localMexos.Start("/tmp/mexosagent.log")
}

//RunMEXAgentManifest runs the MEX agent on the RootLB. It first registers FQDN to cloudflare domain registry if not already registered.
//   It then obtains certficiates from Letsencrypt, if not done yet.  Then it runs the docker instance of MEX agent
//   on the RootLB. It can be told to manually pull image from docker repository.  This allows upgrading with new image.
//   It uses MEX private docker repository.  If an instance is running already, we don't start another one.
func RunMEXAgentManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "run mex agent")

	if IsLocalDIND(mf) {
		return runLocalMexAgent()
	}
	fqdn := mf.Spec.RootLB
	//fqdn is that of the machine/kvm-instance running the agent
	if !valid.IsDNSName(fqdn) {
		return fmt.Errorf("fqdn %s is not valid", fqdn)
	}
	if err := setPlatConfManifest(mf); err != nil {
		return fmt.Errorf("can't set plat conf, %v", err)
	}
	sd, err := GetServerDetails(mf, fqdn)
	if err == nil {
		if sd.Name == fqdn {
			log.DebugLog(log.DebugLevelMexos, "server with same name as rootLB exists", "fqdn", fqdn)
			rootLB, err := getRootLB(fqdn)
			if err != nil {
				return fmt.Errorf("cannot find rootlb %s", fqdn)
			}
			//return RunMEXOSAgentContainer(mf, rootLB)
			return RunMEXOSAgentService(mf, rootLB)
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
	if mf.Spec.ExternalNetwork == "" {
		return fmt.Errorf("missing external network")
	}
	if mf.Spec.Agent.Image == "" {
		return fmt.Errorf("missing agent image")
	}
	if mf.Metadata.Name == "" {
		return fmt.Errorf("missing name")
	}
	log.DebugLog(log.DebugLevelMexos, "record platform config")
	err = EnableRootLB(mf, rootLB)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "can't enable agent", "name", rootLB.Name)
		return fmt.Errorf("Failed to enable root LB %v", err)
	}
	err = WaitForRootLB(mf, rootLB)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "timeout waiting for agent to run", "name", rootLB.Name)
		return fmt.Errorf("Error waiting for rootLB %v", err)
	}
	if err := SetupSSHUser(mf, rootLB, sshUser); err != nil {
		return err
	}
	if err = ActivateFQDNA(mf, rootLB, rootLB.Name); err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "FQDN A record activated", "name", rootLB.Name)
	err = AcquireCertificates(mf, rootLB, rootLB.Name) //fqdn name may be different than rootLB.Name
	if err != nil {
		return fmt.Errorf("can't acquire certificate for %s, %v", rootLB.Name, err)
	}
	log.DebugLog(log.DebugLevelMexos, "acquired certificates from letsencrypt", "name", rootLB.Name)
	//return RunMEXOSAgentContainer(mf, rootLB)
	return RunMEXOSAgentService(mf, rootLB)
}

func RunMEXOSAgentService(mf *Manifest, rootLB *MEXRootLB) error {
	//TODO check if agent is running before restarting again.
	log.DebugLog(log.DebugLevelMexos, "will run new mexosagent service")
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
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
	for _, dest := range []struct{ path, name string }{
		{"/usr/local/bin", "mexosagent"},
		{"/lib/systemd/system", "mexosagent.service"},
	} {
		cmd := fmt.Sprintf("sudo scp -o %s -o %s -i id_rsa_mex mobiledgex@%s:files-repo/mobiledgex/%s %s", sshOpts[0], sshOpts[1], mf.Values.Registry.Name, dest.name, dest.path)
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

func RunMEXOSAgentContainer(mf *Manifest, rootLB *MEXRootLB) error {
	if mexEnv(mf, "MEX_DOCKER_REG_PASS") == "" {
		return fmt.Errorf("empty docker registry pass env var")
	}
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
	if err != nil {
		return err
	}
	//XXX rewrite this with --format {{.Names}}
	cmd := fmt.Sprintf("docker ps --filter ancestor=%s --format {{.Names}}", mf.Spec.Agent.Image)
	out, err := client.Output(cmd)
	if err == nil && strings.Contains(out, rootLB.Name) {
		//agent docker instance exists
		//XXX check better
		log.DebugLog(log.DebugLevelMexos, "agent docker instance already running")
		return nil
	}
	cmd = fmt.Sprintf("echo %s > .docker-pass", mexEnv(mf, "MEX_DOCKER_REG_PASS"))
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't store docker pass, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "seeded docker registry password")
	dockerinstanceName := fmt.Sprintf("%s-%s", mf.Metadata.Name, rootLB.Name)
	if mf.Spec.DockerRegistry == "" {
		log.DebugLog(log.DebugLevelMexos, "warning, empty docker registry spec, using default.")
		mf.Spec.DockerRegistry = mf.Values.Registry.Docker
	}
	cmd = fmt.Sprintf("cat .docker-pass| docker login -u mobiledgex --password-stdin %s", mf.Spec.DockerRegistry)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error docker login at %s, %s, %s, %v", rootLB.Name, cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "docker login ok")
	cmd = fmt.Sprintf("docker pull %s", mf.Spec.Agent.Image) //probably redundant
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error pulling docker image at %s, %s, %s, %v", rootLB.Name, cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "pulled agent image ok")
	cmd = fmt.Sprintf("docker run -d --rm --name %s --net=host -v `pwd`:/var/www/.cache -v /etc/ssl/certs:/etc/ssl/certs %s -debug", dockerinstanceName, mf.Spec.Agent.Image)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error running dockerized agent on RootLB %s, %s, %s, %v", rootLB.Name, cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "now running dockerized mexosagent")
	return nil
}

//UpdateMEXAgentManifest upgrades the mex agent
func UpdateMEXAgentManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "update mex agent")
	err := RemoveMEXAgentManifest(mf)
	if err != nil {
		return err
	}
	// Force pulling a potentially newer docker image
	return RunMEXAgentManifest(mf)
}

//RemoveMEXAgentManifest deletes mex agent docker instance
func RemoveMEXAgentManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "deleting mex agent")
	//XXX we are deleting server kvm!!!
	err := DeleteServer(mf, mf.Spec.RootLB)
	force := strings.Contains(mf.Spec.Flags, "force")
	if err != nil {
		if !force {
			return err
		}
		log.DebugLog(log.DebugLevelMexos, "forced to continue, deleting mex agent error", "error", err, "rootLB", mf.Spec.RootLB)
	}
	log.DebugLog(log.DebugLevelMexos, "removed rootlb", "name", mf.Spec.RootLB)
	sip, err := GetServerIPAddr(mf, mf.Values.Network.External, mf.Spec.RootLB)
	if err := DeleteSecurityRule(mf, sip); err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot delete security rule", "error", err, "server ip", sip)
	}
	if mf.Metadata.DNSZone == "" {
		return fmt.Errorf("missing dns zone in manifest, metadata %v", mf.Metadata)
	}
	if cerr := cloudflare.InitAPI(mexEnv(mf, "MEX_CF_USER"), mexEnv(mf, "MEX_CF_KEY")); cerr != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", cerr)
	}
	recs, derr := cloudflare.GetDNSRecords(mf.Metadata.DNSZone)
	fqdn := mf.Spec.RootLB
	if derr != nil {
		return fmt.Errorf("can not get dns records for %s, %v", fqdn, derr)
	}
	for _, rec := range recs {
		if rec.Type == "A" && rec.Name == fqdn {
			err = cloudflare.DeleteDNSRecord(mf.Metadata.DNSZone, rec.ID)
			if err != nil {
				return fmt.Errorf("cannot delete dns record id %s Zone %s, %v", rec.ID, mf.Metadata.DNSZone, err)
			}
		}
	}
	log.DebugLog(log.DebugLevelMexos, "removed DNS A record", "FQDN", fqdn)
	//TODO remove mex-k8s  internal nets and router
	return nil
}
