package mexos

import (
	"fmt"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/nanobox-io/golang-ssh"
)

var sshOpts = []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "LogLevel=ERROR"}
var sshUser = "ubuntu"

//CopySSHCredential copies over the ssh credential for mex to LB
func CopySSHCredential(mf *Manifest, serverName, networkName, userName string) error {
	//TODO multiple keys to be copied and added to authorized_keys if needed
	log.DebugLog(log.DebugLevelMexos, "copying ssh credentials", "server", serverName, "network", networkName, "user", userName)
	addr, err := GetServerIPAddr(mf, networkName, serverName)
	if err != nil {
		return err
	}
	kf := PrivateSSHKey()
	out, err := sh.Command("scp", "-o", sshOpts[0], "-o", sshOpts[1], "-i", kf, kf, sshUser+"@"+addr+":").Output()
	if err != nil {
		return fmt.Errorf("can't copy %s to %s, %s, %v", kf, addr, out, err)
	}
	return nil
}

//GetSSHClient returns ssh client handle for the server
func GetSSHClient(mf *Manifest, serverName, networkName, userName string) (ssh.Client, error) {
	auth := ssh.Auth{Keys: []string{PrivateSSHKey()}}
	addr, err := GetServerIPAddr(mf, networkName, serverName)
	if err != nil {
		return nil, err
	}
	client, err := ssh.NewNativeClient(userName, addr, "SSH-2.0-mobiledgex-ssh-client-1.0", 22, &auth, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot get ssh client for server %s on network %s, %v", serverName, networkName, err)
	}
	//log.DebugLog(log.DebugLevelMexos, "got ssh client", "addr", addr, "key", auth)
	return client, nil
}

func GetSSHClientIP(mf *Manifest, ipaddr, userName string) (ssh.Client, error) {
	auth := ssh.Auth{Keys: []string{PrivateSSHKey()}}
	client, err := ssh.NewNativeClient(userName, ipaddr, "SSH-2.0-mobiledgex-ssh-client-1.0", 22, &auth, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot get ssh client for ipaddr %s, %v", ipaddr, err)
	}
	return client, nil
}

func SetupSSHUser(mf *Manifest, rootLB *MEXRootLB, user string) error {
	log.DebugLog(log.DebugLevelMexos, "setting up ssh user", "user", user)
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, user)
	if err != nil {
		return err
	}
	// XXX cloud-init creates non root user but it does not populate all the needed files.
	//  packer will create images with correct things for root .ssh. It cannot provision
	//  them for the `ubuntu` user. It may not yet exist until cloud-init runs. So we fix it here.
	for _, cmd := range []string{
		fmt.Sprintf("sudo cp /root/.ssh/config /home/%s/.ssh/", user),
		fmt.Sprintf("sudo chown %s:%s /home/%s/.ssh/config", user, user, user),
		fmt.Sprintf("sudo chmod 600 /home/%s/.ssh/config", user),
		fmt.Sprintf("sudo cp /root/id_rsa_mex /home/%s/", user),
		fmt.Sprintf("sudo chown %s:%s   /home/%s/id_rsa_mex", user, user, user),
		fmt.Sprintf("sudo chmod 600   /home/%s/id_rsa_mex", user),
	} {
		out, err := client.Output(cmd)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error setting up ssh user",
				"user", user, "error", err, "out", out)
			return err
		}
	}
	return nil
}
