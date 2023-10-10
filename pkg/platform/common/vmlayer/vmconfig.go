// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vmlayer

import (
	"fmt"

	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
)

var VmCloudConfig = `#cloud-config
bootcmd:
 - echo EDGECLOUD CONFIG START
 - echo 'APT::Periodic::Enable "0";' > /etc/apt/apt.conf.d/10cloudinit-disable
 - apt-get -y purge update-notifier-common ubuntu-release-upgrader-core landscape-common
 - echo "Removed APT and Ubuntu extra packages" | systemd-cat
 - cloud-init-per once ssh-users-ca echo "TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem" >> /etc/ssh/sshd_config
{{- range .ExtraBootCommands}}
 - {{.}}
{{- end}}
write_files:
  - path: /etc/ssh/trusted-user-ca-keys.pem
    content: {{ .CACert }}
    append: true
  - path:  /etc/systemd/resolved.conf
    content: |
       [Resolve]
       DNS={{.PrimaryDNS}}
       {{- if .FallbackDNS}}
       FallbackDNS={{.FallbackDNS}}
       {{- end}}
{{- if .ConfigureNodeVars }}
  - path: /root/configure-node.sh
    owner: root:root
    permissions: '0700'
    content: |
{{ Indent .ConfigureNodeVars.ConfigureNodeScript 10 }}
  - path: /etc/cron.d/configure-node
    owner: root:root
    permissions: '0644'
    content: |
      */10 * * * * root /root/configure-node.sh >> /root/configure-node.log 2>&1
  - path: /etc/logrotate.d/configure-node
    owner: root:root
    permissions: '0644'
    content: |
      /root/configure-node.log {
        rotate 4
        daily
        compress
        missingok
        notifempty
        size 10M
      }
{{- end}}
  {{- if .NtpServers}}
  - path:  /etc/systemd/timesyncd.conf
    content: |
       [Time]
       NTP={{.NtpServers}}
  {{- end}}
{{- if .AccessKey }}
  - path: /root/accesskey/accesskey.pem
    content: |
{{ Indent .AccessKey 10 }}
    owner: root:root
    permissions: '0600'
{{- end}}
chpasswd: { expire: False }
ssh_pwauth: False
timezone: UTC
{{- if .ConfigureNodeVars }}
apt:
  sources:
    ansible-ppa:
      source: ppa:ansible/ansible
packages:
- [ansible, 8.4.0-1ppa~jammy]
{{- end}}
runcmd:
 - systemctl restart systemd-resolved
 {{- if .NtpServers}}
 - systemctl restart systemd-timesyncd
 {{- end}}
 - echo EDGECLOUD doing ip addr show
 - ip addr show
 - /root/configure-node.sh >> /root/configure-node.log 2>&1`

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

func GetVMUserData(name string, sharedVolume bool, manifest, command string, cloudConfigParams *VMCloudConfigParams, formatter VmConfigDataFormatter) (string, error) {
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
		if cloudConfigParams.ConfigureNodeVars != nil {
			err := cloudConfigParams.ConfigureNodeVars.GenScript()
			if err != nil {
				return "", err
			}
		}
		rc = VmCloudConfig
		buf, err := infracommon.ExecTemplate(name, VmCloudConfig, cloudConfigParams)
		if err != nil {
			return "", fmt.Errorf("failed to generate template from cloud config params %v, err %v", cloudConfigParams, err)
		}
		rc = buf.String()
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
	if role == RoleMaster || role == RoleK8sNode {
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
