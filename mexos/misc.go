package mexos

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
)

const HTPasswdFile = "nginx.htpasswd"

func PrivateSSHKey() string {
	return MEXDir() + "/id_rsa_mex"
}

func MEXDir() string {
	return os.Getenv("HOME") + "/.mobiledgex"
}

func defaultKubeconfig() string {
	return os.Getenv("HOME") + "/.kube/config"
}

func copyFile(src string, dst string) error {
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

func writeKubeManifest(kubeManifest string, filename string) error {
	outFile, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to open k8s deployment file %s: %s", filename, err.Error())
	}
	_, err = outFile.WriteString(kubeManifest)
	if err != nil {
		outFile.Close()
		os.Remove(filename)
		return fmt.Errorf("unable to write k8s deployment file %s: %s", filename, err.Error())
	}
	outFile.Sync()
	outFile.Close()
	return nil
}

func NormalizeName(name string) string {
	return util.K8SSanitize(name) // XXX
}

func SeedDockerSecret(mf *Manifest, rootLB *MEXRootLB) error {
	log.DebugLog(log.DebugLevelMexos, "seed docker secret")
	name, err := FindClusterWithKey(mf, mf.Spec.Key)
	if err != nil {
		return err
	}
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
	if err != nil {
		return fmt.Errorf("can't get ssh client for docker swarm, %v", err)
	}
	masteraddr, err := FindNodeIP(mf, name)
	if err != nil {
		return err
	}
	var out string
	cmd := fmt.Sprintf("echo %s > .docker-pass", mexEnv(mf, "MEX_DOCKER_REG_PASS"))
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
	cmd = fmt.Sprintf("ssh -o %s -o %s -i id_rsa_mex %s 'cat .docker-pass| docker login -u mobiledgex --password-stdin %s'", sshOpts[0], sshOpts[1], masteraddr, mf.Values.Registry.Docker)
	//TODO allow different docker registry as specified in the manifest
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't docker login on k8s-master to %s, %s, %v", mf.Values.Registry.Docker, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "docker login ok")
	return nil
}

func GetHTPassword(mf *Manifest, rootLB *MEXRootLB) error {
	log.DebugLog(log.DebugLevelMexos, "get htpasswd")
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
	if err != nil {
		return fmt.Errorf("can't get ssh client for docker swarm, %v", err)
	}
	cmd := fmt.Sprintf("scp -o %s -o %s -i id_rsa_mex mobiledgex@%s:files-repo/mobiledgex/%s .", sshOpts[0], sshOpts[1], mf.Values.Registry.Name, HTPasswdFile)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't get htpasswd file, %v, %s", err, out)
	}
	log.DebugLog(log.DebugLevelMexos, "downloaded htpasswd")
	return nil
}
