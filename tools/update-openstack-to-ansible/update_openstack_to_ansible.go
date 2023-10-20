// Helper program to update openstack (or VM-based platform)
// platform VMs to use ansible instead of chef.

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/toollib"
	ssh "github.com/edgexr/golang-ssh"
	gossh "golang.org/x/crypto/ssh"
)

var domain string
var region string

var sshUser = "ubuntu"
var sshTimeout = 5 * time.Second
var SSHOpts = []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "LogLevel=ERROR"}

const sshClientVersion = "SSH-2.0-edgecloud-ssh-client-1.0"

func main() {
	flag.StringVar(&domain, "domain", "", "deployment domain")
	flag.StringVar(&region, "region", "", "region")
	flag.Parse()

	if domain == "" {
		log.Fatal("domain must be specified")
	}
	if region == "" {
		log.Fatal("region must be specified")
	}

	mcClient, addr, token, err := toollib.GetMCClient(domain)
	if err != nil {
		log.Fatalf("get MC client failed, %s\n", err.Error())
	}

	// prepare ssh config
	sshAuth, err := toollib.GetSSHAuth(domain, "", "")
	if err != nil {
		log.Fatalf("get ssh auth failed, %s\n", err.Error())
	}

	sshConfig, err := ssh.NewNativeConfig(sshUser, sshClientVersion, sshAuth, sshTimeout, nil)
	if err != nil {
		log.Fatalf("get ssh config failed, %s\n", err.Error())
	}

	// get existing cloudlet nodes
	nodes, st, err := mcClient.ShowCloudletNode(addr, token, &ormapi.RegionCloudletNode{Region: region})
	if err != nil {
		log.Fatalf("show cloudlet nodes failed, %s\n", err.Error())
	}
	if st != http.StatusOK {
		log.Fatalf("show CloudletNode status %d", st)
	}
	nodeLookup := make(map[edgeproto.CloudletNodeKey]*edgeproto.CloudletNode)
	for _, node := range nodes {
		nodeLookup[node.Key] = &node
	}

	// get cloudlet infos
	infos, st, err := mcClient.ShowCloudletInfo(addr, token, &ormapi.RegionCloudletInfo{Region: region})
	if err != nil {
		log.Fatalf("show cloudlet infos failed, %s\n", err.Error())
	}
	if st != http.StatusOK {
		log.Fatalf("show CloudletInfo status %d", st)
	}

	failed := 0
	passed := 0
	for _, info := range infos {
		for _, pvm := range info.ResourcesSnapshot.PlatformVms {
			log.Print("-------------------------------------------")
			log.Printf("setting up node %s...\n", pvm.Name)
			err := setupNode(mcClient, addr, token, nodeLookup, &info, &pvm, sshConfig)
			if err != nil {
				log.Printf("setup node failed for %s, %s\n", pvm.Name, err)
				failed++
			} else {
				passed++
			}
		}
	}
	log.Printf("Ok: %d, Failed: %d\n", passed, failed)
}

func setupNode(mcClient *mctestclient.Client, addr, token string, nodeLookup map[edgeproto.CloudletNodeKey]*edgeproto.CloudletNode, info *edgeproto.CloudletInfo, pvm *edgeproto.VmInfo, sshConfig gossh.ClientConfig) (reterr error) {
	// only handling platformVM types
	nodeType := cloudcommon.NodeTypePlatformVM
	if pvm.Type != nodeType.String() {
		log.Printf("  skipping node type %s\n", pvm.Type)
		return nil
	}
	var ip string
	for _, ips := range pvm.Ipaddresses {
		if ips.ExternalIp != "" {
			ip = ips.ExternalIp
			break
		}
	}
	if ip == "" {
		return fmt.Errorf("no external IP found")
	}
	log.Printf("  using ip %s\n", ip)

	sshClient, err := ssh.NewNativeClientWithConfig(ip, 22, sshConfig)
	if err != nil {
		return err
	}

	node := edgeproto.CloudletNode{
		Key: edgeproto.CloudletNodeKey{
			Name:        pvm.Name,
			CloudletKey: info.Key,
		},
		NodeType:  nodeType.String(),
		NodeRole:  cloudcommon.NodeRoleDockerCrm.String(),
		OwnerTags: info.Key.GetTags(),
	}
	if _, found := nodeLookup[node.Key]; found {
		// already present
		log.Printf("  skipping node %s that already has a CloudletNode\n", pvm.Type)
		return nil
	}

	// check if node can be upgraded
	out, err := sshClient.Output("lsb_release -a")
	if err != nil {
		return fmt.Errorf("lsb_release cmd failed:\n%s\n%s", out, err)
	}
	if !strings.Contains(out, "Ubuntu 18.04") {
		return fmt.Errorf("this upgrade is only for Ubuntu 18.04 nodes because it builds python3.9 from source, because python3.9 is not available otherwise for Ubuntu 18.04. If this is not Ubuntu 18.04, there may be better ways to install python3.9.")
	}

	// create CloudletNode
	log.Printf("  creating CloudletNode\n")
	rnode := ormapi.RegionCloudletNode{
		Region:       region,
		CloudletNode: node,
	}
	res, st, err := mcClient.CreateCloudletNode(addr, token, &rnode)
	if err != nil {
		log.Fatal(err.Error())
	}
	if st != http.StatusOK {
		log.Fatalf("Create CloudletNode status %d", st)
	}
	defer func() {
		if reterr == nil {
			return
		}
		// if something failed, delete cloudlet node so we can try again
		_, st, err := mcClient.DeleteCloudletNode(addr, token, &rnode)
		if err != nil || st != http.StatusOK {
			log.Printf("cleaning up failed cloudlet node hit error, %d %s", st, err)
		}
	}()

	// Note: The ansible scripts we use to deploy the CRM
	// depend on a newer version of ansible that has a recent
	// community.docker module. That in turn depends on
	// python3.9. Ubuntu 18.04 does not have any official or
	// unofficial python3.9 packages, so we install from source.
	installPython := `#!/bin/bash
set -e
if python3.9 --version; then
  echo "python3.9 already installed"
  exit 0
fi
cd /root
sudo apt update -y
sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev -y
mkdir -p tmp && cd tmp
rm -Rf Python-3.9.11
wget https://www.python.org/ftp/python/3.9.11/Python-3.9.11.tgz
tar -xf Python-3.9.11.tgz
cd Python-3.9.11
./configure --enable-optimizations
make altinstall
`

	password := res.Message

	log.Printf("  generating configure-node script\n")
	cfg := confignode.ConfigureNodeVars{}
	cfg.Key.Name = node.Key.Name
	cfg.Key.CloudletKey = node.Key.CloudletKey
	cfg.NodeType = nodeType
	cfg.NodeRole = cloudcommon.NodeRoleDockerCrm
	cfg.Password = password
	cfg.AnsiblePublicAddr = "https://ansible." + domain
	err = cfg.GenScript()
	if err != nil {
		return fmt.Errorf("failed to generate configure-node.sh, %s", err)
	}

	logRotate := `/root/configure-node.log {
	rotate 4
	daily
	compress
	missingok
	notifempty
	size 10M
}
`

	cronJob := `*/10 * * * * root /root/configure-node.sh >> /root/configure-node.log 2>&1\n`

	// write files to machine
	type File struct {
		name     string
		contents string
		perms    string
	}
	files := []File{{
		"/root/installPython.sh", installPython, "0700",
	}, {
		"/root/configure-node.sh", cfg.ConfigureNodeScript, "0700",
	}, {
		"/etc/logrotate.d/configure-node", logRotate, "0644",
	}, {
		"/etc/cron.d/configure-node", cronJob, "0644",
	}}
	for _, file := range files {
		log.Printf("  writing file %s\n", file.name)
		err = WriteFile(sshClient, file.name, file.contents, file.perms)
		if err != nil {
			return fmt.Errorf("failed to write file %q: %s", file.name, err)
		}
	}

	// run commands
	cmds := []string{
		"sudo -i PWD=/root /root/installPython.sh",
		"sudo pip3.9 install requests ansible",
		"sudo -i PWD=/root ansible-galaxy collection install community.docker",
		"sudo -i PWD=/root /root/configure-node.sh",
		"sudo systemctl stop chef-client",
	}
	for _, cmd := range cmds {
		log.Printf("  " + cmd)
		out, err := sshClient.Output(cmd)
		if err != nil {
			return fmt.Errorf("command failed: %s\n%s", out, err)
		}
	}
	log.Printf("  completed\n")
	return nil
}

func WriteFile(sshClient ssh.Client, file, contents, perms string) error {
	err := pc.WriteFile(sshClient, file, contents, file, pc.SudoOn)
	if err != nil {
		return err
	}
	out, err := sshClient.Output("sudo chmod " + perms + " " + file)
	if err != nil {
		return fmt.Errorf("%s, %s", out, err)
	}
	return nil
}
