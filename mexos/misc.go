package mexos

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

const HTPasswdFile = "nginx.htpasswd"

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

func SeedDockerSecret(client pc.PlatformClient, inst *edgeproto.ClusterInst, singleNode bool) error {
	log.DebugLog(log.DebugLevelMexos, "seed docker secret", "singleNode", singleNode)

	if singleNode {
		cmd := fmt.Sprintf("docker login %s -u %s -p %s", GetCloudletDockerRegistry(), "mobiledgex", GetCloudletDockerPass())
		//TODO allow different docker registry as specified in the manifest
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("can't docker login on rootlb to %s, %s, %v", GetCloudletDockerRegistry(), out, err)
		}
		return nil
	}
	_, masteraddr, err := GetMasterNameAndIP(inst)
	if err != nil {
		return err
	}
	var out string
	cmd := fmt.Sprintf("echo %s > .docker-pass", GetCloudletDockerPass())
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't store docker password, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "stored docker password")
	cmd = fmt.Sprintf("scp -o %s -o %s -i id_rsa_mex .docker-pass %s:", sshOpts[0], sshOpts[1], masteraddr)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't copy docker password to k8s-master, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "copied over docker password")
	cmd = fmt.Sprintf("ssh -o %s -o %s -i id_rsa_mex %s 'cat .docker-pass| docker login -u mobiledgex --password-stdin %s'", sshOpts[0], sshOpts[1], masteraddr, GetCloudletDockerRegistry())
	//TODO allow different docker registry as specified in the manifest
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't docker login on k8s-master to %s, %s, %v", GetCloudletDockerRegistry(), out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "docker login ok")
	return nil
}

func GetHTPassword(rootLBName string) error {
	log.DebugLog(log.DebugLevelMexos, "get htpasswd")
	client, err := GetSSHClient(rootLBName, GetCloudletExternalNetwork(), SSHUser)
	if err != nil {
		return fmt.Errorf("can't get ssh client for docker swarm, %v", err)
	}
	cmd := fmt.Sprintf("scp -o %s -o %s -i id_rsa_mex mobiledgex@%s:files-repo/mobiledgex/%s .", sshOpts[0], sshOpts[1], GetCloudletRegistryFileServer(), HTPasswdFile)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't get htpasswd file, %v, %s", err, out)
	}
	log.DebugLog(log.DebugLevelMexos, "downloaded htpasswd")
	return nil
}
