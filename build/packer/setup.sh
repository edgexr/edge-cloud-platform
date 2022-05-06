#!/bin/bash
# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PATH='/usr/bin:/bin'; export PATH

LOGDIR="/etc/mobiledgex"
LOGFILE="${LOGDIR}/creation_log.txt"
DEFAULT_INTERFACE=ens3
ARTIFACTORY_BASEURL='https://artifactory.mobiledgex.net'
MEX_RELEASE=/etc/mex-release

TMPLOG="/var/tmp/creation_log.txt"
exec &> >(tee "$TMPLOG")

[[ "$TRACE" == yes ]] && set -x
set -e

sudo mkdir -p "$LOGDIR"
sudo chmod 700 "$LOGDIR"

# Move log file into 
archive_log() {
	[[ -f "$LOGFILE" ]] \
		&& sudo mv "$LOGFILE" "${LOGFILE}.$( date +'%Y-%m-%d-%H%M' )"
	sudo mv "$TMPLOG" "$LOGFILE"
}
trap 'archive_log' EXIT

[[ "$PACKER_BUILD_NAME" == debug ]] && DEBUG_BUILD=true || DEBUG_BUILD=false

$DEBUG_BUILD && ROOT_PASS="$DEBUG_ROOT_PASS"

if [[ -z "$ROOT_PASS" ]]; then
	echo "Root password not found" >&2
	exit 2
elif [[ -z "$GRUB_PW_HASH" ]]; then
	echo "GRUB password hash not found" >&2
	exit 2
elif [[ -z "$TOTP_KEY" ]]; then
	echo "TOTP key not found" >&2
	exit 2
fi

# Defaults for environment variables
: ${TAG:=master}
: ${VAULT:=vault-main.mobiledgex.net}

if [[ -z "$INTERFACE" ]]; then
	INTERFACE=$( ls -d /sys/class/net/*/device 2>/dev/null \
			| head -n 1 \
			| cut -d/ -f5 )
	if [[ -z "$INTERFACE" ]]; then
		log "Unable to determine default interface; assuming $DEFAULT_INTERFACE"
		INTERFACE=$DEFAULT_INTERFACE
	fi
fi

log() {
	echo "[$(date)] $*"
}

log_file_contents() {
	[[ -f "$1" ]] || return

	echo "::::::::::  $1  ::::::::::"
	cat "$1"
	echo "::::::::::::::::::::::::::"
	echo
}

die() {
	log "FATAL: $*"
	exit 2
}

# Main
[[ -z "$APT_REPO" ]] && die "APT_REPO not set"

echo "[$(date)] Starting setup.sh ($( pwd ))"

echo "127.0.0.1 $( hostname )" | sudo tee -a /etc/hosts >/dev/null
log_file_contents /etc/hosts

sudo tee /etc/systemd/resolved.conf <<EOT
[Resolve]
DNS=1.1.1.1 1.0.0.1
FallbackDNS=8.8.8.8
EOT
sudo tee -a /etc/resolv.conf >/dev/null <<EOT
nameserver 1.1.1.1
nameserver 1.0.0.1
EOT
log_file_contents /etc/resolv.conf

log "Setting up $MEX_RELEASE"
sudo tee "$MEX_RELEASE" <<EOT
MEX_BUILD="$MEX_BUILD $( TZ=UTC date +'%Y/%m/%d %H:%M %Z' )"
MEX_BUILD_TAG=$TAG
MEX_BUILD_FLAVOR=$FLAVOR
MEX_BUILD_IMG_TYPE=$PACKER_BUILD_NAME
MEX_BUILD_SRC_IMG=$SRC_IMG
MEX_BUILD_SRC_IMG_CHECKSUM=$SRC_IMG_CHECKSUM
EOT

SSH_CA_KEY_FILE=/etc/ssh/trusted-user-ca-keys.pem
VAULT_URL="https://${VAULT}/v1/ssh/public_key"
log "Set up SSH CA key: $VAULT_URL"
curl --silent --fail "$VAULT_URL" | sudo tee "$SSH_CA_KEY_FILE"
grep "ssh-rsa" "$SSH_CA_KEY_FILE" >/dev/null 2>&1
echo "TrustedUserCAKeys $SSH_CA_KEY_FILE" | sudo tee -a /etc/ssh/sshd_config

log "Set up docker log file rotation"
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<EOT
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "20"
  }
}
EOT

sudo tee /etc/apt/auth.conf.d/mobiledgex.net.conf <<EOT
machine artifactory.mobiledgex.net login ${APT_USER} password ${APT_PASS}
machine apt.mobiledgex.net login ${APT_USER} password ${APT_PASS}
EOT

log "Set up the APT keys"
curl -s https://${APT_USER}:${APT_PASS}@artifactory.mobiledgex.net/artifactory/api/gpg/key/public | sudo apt-key add -
curl -s https://${APT_USER}:${APT_PASS}@apt.mobiledgex.net/gpg.key | sudo apt-key add -

ps -ef | grep cloud

log "Set up APT sources"
sudo rm -rf /etc/apt/sources.list.d/*
sudo tee /etc/apt/sources.list <<EOT
deb ${APT_REPO} bionic main
deb https://artifactory.mobiledgex.net/artifactory/packages cirrus main
EOT
sudo apt-get update
sudo env UCF_FORCE_CONFFOLD=1 apt-get upgrade -y

log "Disable cloud config overwrite of APT sources"
sudo tee -a /etc/cloud/cloud.cfg <<EOT
# Preserve /etc/apt/sources.list
apt_preserve_sources_list: true
EOT

log "Disable snap"
sudo apt purge -y snapd
sudo rm -rf /snap /var/snap /var/cache/snapd /var/lib/snapd

# Remove systemd-networkd-wait-online as it often hangs with netplan which we use in 18.04
log "disable systemd-networkd-wait-online"
sudo systemctl mask systemd-networkd-wait-online

log "Remove unnecessary packages"
cat /tmp/pkg-cleanup.txt | sudo xargs apt-get purge -y
sudo rm -f /tmp/pkg-cleanup.txt

if ! $DEBUG_BUILD; then
	log "Set up GRUB password"
	sudo tee /etc/grub.d/50_grub_pw <<EOT
cat <<PW
set superusers="root"
password_pbkdf2 root $GRUB_PW_HASH
PW
EOT
	sudo chmod a+x /etc/grub.d/50_grub_pw
fi

# Allow boot without requiring passwords
sudo sed -i '/^CLASS=/s/"$/ --unrestricted"/' /etc/grub.d/10_linux
sudo update-grub

log "Install mobiledgex ${TAG#v}"
# avoid interactive for iptables-persistent
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
# Pin mobiledgex package version
sudo tee /etc/apt/preferences.d/mobiledgex.pref <<EOT
Package: mobiledgex
Pin: version ${TAG#v}
Pin-Priority: 1001
EOT
sudo apt-get install -y mobiledgex
[[ $? -ne 0 ]] && die "Failed to install extra packages"

sudo apt-mark hold mobiledgex linux-image-generic linux-image-virtual

log "Adding VMWare cloud-init Guestinfo"
sudo curl  -sSL https://raw.githubusercontent.com/vmware/cloud-init-vmware-guestinfo/v1.3.1/install.sh |sudo sh -
sudo rm -f /etc/cloud/cloud.cfg.d/99-DataSourceVMwareGuestInfo.cfg
sudo tee /etc/cloud/cloud.cfg.d/99-mobiledgex.cfg <<'EOT'
datasource_list: [ "ConfigDrive", "OVF", "VMwareGuestInfo" ]
EOT

log "dhclient $INTERFACE"
sudo dhclient "$INTERFACE"
ip addr
ip route

log "Updating dhclient timeout"
sudo perl -i -p -e s/'timeout 300;'/'timeout 15;'/g /etc/dhcp/dhclient.conf

log "Removing serial console from grub"
sudo perl -i -p -e s/'"console=tty1 console=ttyS0"'/'""'/g /etc/default/grub.d/50-cloudimg-settings.cfg
sudo grub-mkconfig -o /boot/grub/grub.cfg

log "Setting the root password"
echo "root:$ROOT_PASS" | sudo chpasswd

if ! $DEBUG_BUILD; then
	log "Setting up root TOTP"
	sudo apt-get install -y libpam-google-authenticator
	echo "auth required pam_google_authenticator.so" \
		| sudo tee -a /etc/pam.d/login
	sudo tee /root/.google_authenticator >/dev/null <<EOT
$TOTP_KEY
" RATE_LIMIT 3 30
" WINDOW_SIZE 17
" DISALLOW_REUSE
" TOTP_AUTH
EOT
	sudo chmod 400 /root/.google_authenticator
fi

# Fetch kubeadm package version
K8SVERS=$( dpkg -l | grep kubeadm | awk '{print $3}' | cut -d- -f1 )

log "Pulling docker images for kubernetes $K8SVERS"
sudo kubeadm config images pull --kubernetes-version "$K8SVERS"
for DOCKER_IMAGE in $( cat /tmp/docker-image-cache.txt ); do
	sudo docker pull --quiet "$DOCKER_IMAGE"
done

log "Cached docker images"
sudo docker image ls

log "System setup"
sudo swapoff -a
sudo sed -i "s/cgroup-driver=systemd/cgroup-driver=cgroupfs/g" /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
sudo usermod -aG docker root

echo "d /run/sshd 0755 root root" | sudo tee -a /usr/lib/tmpfiles.d/sshd.conf
sudo rm -f /etc/systemd/system/ssh.service
sudo tee /etc/systemd/system/ssh.service <<'EOT'
[Unit]
Description=OpenBSD Secure Shell server
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
Type=notify

[Install]
WantedBy=multi-user.target
Alias=sshd.service
EOT

sudo tee /etc/cron.hourly/sshd-stale-session-cleanup <<'EOT'
#!/bin/sh
systemctl 2>/dev/null \
    | grep 'scope.*abandoned' \
    | awk '{print $1}' \
    | sudo xargs -r systemctl stop >>/var/tmp/session-cleanup.log 2>&1
EOT
sudo chmod +x /etc/cron.hourly/sshd-stale-session-cleanup

# Create Chef related files required during cloud-init
sudo mkdir -p /etc/chef
sudo touch /etc/chef/client.rb

# systemd unit file for chef-client
sudo tee /etc/default/chef-client <<'EOT'
# Chef client config file
CONFIG=/etc/chef/client.rb

# Interval in seconds
INTERVAL=600

# Splay interval in seconds
SPLAY=20

# Other options
OPTIONS="-d 1 --chef-license accept"
EOT

sudo tee /etc/systemd/system/chef-client.service <<'EOT'
[Unit]
Description = Chef Client daemon
After = network.target auditd.service

[Service]
Type = forking
EnvironmentFile = /etc/default/chef-client
PIDFile = /var/run/chef/client.pid
ExecStart = /usr/bin/chef-client -c $CONFIG -i $INTERVAL -s $SPLAY $OPTIONS
ExecReload = /bin/kill -HUP $MAINPID
SuccessExitStatus = 3
Restart = always

[Install]
WantedBy = multi-user.target
EOT

log "Enabling the chef-client service"
sudo systemctl enable chef-client

sudo tee /etc/systemd/system/k8s-join.service <<'EOT'
[Unit]
Description=Job that runs k8s join script server

[Service]
Type=simple
WorkingDirectory=/var/tmp/k8s-join
ExecStart=/usr/bin/python3 -m http.server 20800
Restart=always

[Install]
WantedBy=multi-user.target
EOT

sudo tee /lib/systemd/system/open-vm-tools.service <<'EOT'
[Unit]
Description=Service for virtual machines hosted on VMware
Documentation=http://open-vm-tools.sourceforge.net/about.php
ConditionVirtualization=vmware
DefaultDependencies=no
Requires=dbus.socket
After=dbus.socket
[Service]
ExecStart=/usr/bin/vmtoolsd
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOT

log "Enabling the open-vm-tools service"
sudo systemctl enable open-vm-tools

# Clear /etc/machine-id so that it is uniquely generated on every clone
echo "" | sudo tee /etc/machine-id

# Set up temp directory used by install-k8s-master.sh
sudo mkdir /var/tmp/k8s-join

log "Package list"
dpkg -l

echo "[$(date)] Done setup.sh ($( pwd ))"
