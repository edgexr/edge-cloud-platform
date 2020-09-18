package vmlayer

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
)

var VmCloudConfig = `#cloud-config
chef:
  server_url: {{.ServerPath}}
  node_name: {{.NodeName}}
  environment: ""
  validation_name: mobiledgex-validator
  validation_key: /etc/chef/client.pem
  validation_cert: |
{{ Indent .ClientKey 10 }}
bootcmd:
 - echo MOBILEDGEX CLOUD CONFIG START
 - echo 'APT::Periodic::Enable "0";' > /etc/apt/apt.conf.d/10cloudinit-disable
 - apt-get -y purge update-notifier-common ubuntu-release-upgrader-core landscape-common unattended-upgrades
 - echo "Removed APT and Ubuntu extra packages" | systemd-cat
chpasswd: { expire: False }
ssh_pwauth: False
timezone: UTC
runcmd:
 - echo MOBILEDGEX doing ifconfig
 - ifconfig -a`

// vmCloudConfigShareMount is appended optionally to vmCloudConfig.   It assumes
// the end of vmCloudConfig is runcmd
var VmCloudConfigShareMount = `
 - chown nobody:nogroup /share
 - chmod 777 /share 
 - systemctl enable nfs-kernel-server
 - systemctl start nfs-kernel-server
 - echo "/share *(rw,sync,no_subtree_check,no_root_squash)" >> /etc/exports
 - exportfs -a
 - echo "showing exported filesystems"
 - exportfs
disk_setup:
  /dev/vdb:
    table_type: 'gpt'
    overwrite: true
    layout: true
fs_setup:
 - label: share_fs
   filesystem: 'ext4'
   device: /dev/vdb
   partition: auto
   overwrite: true
   layout: true
mounts:
 - [ "/dev/vdb", "/share" ]`

// VmConfigDataFormatter formats user or meta data to fit into orchestration templates
type VmConfigDataFormatter func(instring string) string

func GetVMUserData(sharedVolume bool, dnsServers, manifest, command string, chefParams *chefmgmt.VMChefParams, formatter VmConfigDataFormatter) (string, error) {
	var rc string
	if manifest != "" {
		return formatter(manifest), nil
	}
	if command != "" {
		rc = `
#cloud-config
runcmd:
- ` + command
	} else {
		rc = VmCloudConfig
		if chefParams != nil {
			buf, err := ExecTemplate(chefParams.NodeName, VmCloudConfig, chefParams)
			if err != nil {
				return "", fmt.Errorf("failed to generate template from chef params %v, err %v", chefParams, err)
			}
			rc = buf.String()
		}
		if dnsServers != "" {
			rc += fmt.Sprintf("\n - echo \"dns-nameservers %s\" >> /etc/network/interfaces.d/50-cloud-init.cfg", dnsServers)
		}
		if sharedVolume {
			return formatter(rc + VmCloudConfigShareMount), nil
		}
	}
	return formatter(rc), nil
}

func GetVMMetaData(role VMRole, masterIP string, formatter VmConfigDataFormatter) string {
	var str string
	if role == RoleVMApplication {
		return ""
	}
	skipk8s := SkipK8sYes
	if role == RoleMaster || role == RoleNode {
		skipk8s = SkipK8sNo
	}
	str = `skipk8s: ` + string(skipk8s) + `
role: ` + string(role)
	if masterIP != "" {
		str += `
k8smaster: ` + masterIP
	}
	return formatter(str)
}
