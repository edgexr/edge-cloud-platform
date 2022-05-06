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

# this is run at system init time
# TODO: mark so that it does not run again 

set -x

. /etc/mex-release

# this should be revisited to see if it is really needed
systemctl status open-vm-tools > /var/log/openvmtool.status.log
systemctl start open-vm-tools

INIT_COMPLETE_FLAG=/etc/mobiledgex/init-complete
if [[ -f "$INIT_COMPLETE_FLAG" ]]; then
	echo "Already initialized; nothing to do" >&2
	exit 2
fi

umask 027
LOGFILE=/var/log/mobiledgex.log
log() {
	if [[ $# -gt 0 ]]; then
		echo "[$(date)] $*" | tee -a "$LOGFILE"
	else
		echo "[$(date)]"
		tee -a "$LOGFILE"
	fi
}

usermod -aG docker ubuntu
chmod a+rw /var/run/docker.sock

ifconfig -a | log
ip route | log

MCONF=/mnt/mobiledgex-config
METADIR="$MCONF/openstack/latest"
METADATA="$METADIR/meta_data.json"
VMWARE_CLOUDINIT=/etc/cloud/cloud.cfg.d/99-DataSourceVMwareGuestInfo.cfg

# Main
log "Starting mobiledgex init"

# CIS cleanup
chmod u-x,go-rwx /etc/passwd-
chmod u-x,go-rwx /etc/shadow-
chmod og-rwx /boot/grub/grub.cfg
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +

# Customise for vCD, vSphere, or OpenStack
if vmtoolsd --cmd "info-get guestinfo.ovfEnv" > /var/log/userdata.log; then
	log "Running in vCD"
	mkdir -p $METADIR
	if ! /usr/local/bin/parseovfenv > $METADATA; then
		log "error in parseovfenv, quitting"
		log "Finished mobiledgex init"
		exit
	fi
elif vmtoolsd --cmd "info-get guestinfo.metadata"; then
	log "Running in vSphere"
	if ! vmtoolsd --cmd "info-get guestinfo.userdata" > /var/log/userdata.log; then
		log "error getting guestinfo.userdata, quitting"
		log "Finished mobiledgex init"
		exit 1
	fi

	mkdir -p $METADIR
	if ! vmtoolsd --cmd "info-get guestinfo.metadata"|base64 -d|python3 -c 'import sys, yaml, json; json.dump(yaml.load(sys.stdin), sys.stdout)' > $METADATA;
	then
                log "error handling guestinfo.metadata, quitting"
                log "Finished mobiledgex init"
                exit 1
        fi
else
	log "Running in OpenStack"
	mkdir -p $MCONF
	START=$( date +'%s' )
	while (( $( date +'%s' ) - START < 180 )); do
		MCONF_DEV=$( blkid -t LABEL="config-2" -odevice )
		[[ -n "$MCONF_DEV" ]] && break
		log "Waiting for config device..."
		sleep 5
	done
	if [[ -z "$MCONF_DEV" ]]; then
		log "Failed to identify config device"
		exit 2
	fi
	mount "$MCONF_DEV" "$MCONF"
fi

# Load parameters
set_param() {
	local file="$1"
	local var="$2"
	local param="$3"
	local val=$( jq -r "$param // empty" "$file" )
	eval "$var='$val'"
}

# Set variable based on JSON path in metadata file
set_metadata_param() {
	set_param "$METADATA" "$@"
}


set_metadata_param HOSTNAME .name
set_metadata_param UPDATE .meta.update
set_metadata_param SKIPINIT .meta.skipinit
set_metadata_param ROLE .meta.role
set_metadata_param SKIPK8S .meta.skipk8s
set_metadata_param MASTERADDR .meta.k8smaster
set_metadata_param UPDATEHOSTNAME .meta.updatehostname

echo 127.0.0.1 `hostname` >> /etc/hosts
[[ "$UPDATEHOSTNAME" == yes ]] && sed -i "s|^\(127\.0\.1\.1 \).*|\1${HOSTNAME}|" /etc/hosts

if [[ "$SKIPINIT" == yes ]]; then
	log "Skipping mobiledgex init as instructed"
	exit 0
fi

# TODO: Updates; and also if supported, disable run-once flag check at the top

if [[ -z "$ROLE" ]]; then
        log "WARNING: Role is empty"
else
        log "ROLE: $ROLE"
fi

if [[ "$ROLE" == mex-agent-node ]]; then
	log "Initializing mex agent node"
	for SVC in kubelet k8s-join; do
		systemctl disable "$SVC"
		systemctl stop "$SVC"
	done
elif [[ "$SKIPK8S" == yes ]]; then
	log "Skipping k8s init for role $ROLE"
	for SVC in kubelet k8s-join; do
		systemctl disable "$SVC"
		systemctl stop "$SVC"
	done
else
	log "K8s init for role $ROLE"
	case "$ROLE" in
	k8s-master)
		sh -x /etc/mobiledgex/install-k8s-master.sh $MASTERADDR  | log
		if [[ "${PIPESTATUS[0]}" != 0 ]]; then
			log "K8s master init failed"
			exit 2
		fi
		systemctl enable k8s-join
		systemctl start k8s-join
		;;
	k8s-node)
		sh -x /etc/mobiledgex/install-k8s-node.sh $MASTERADDR | log
		if [[ "${PIPESTATUS[0]}" != 0 ]]; then
			log "K8s node init failed"
			exit 2
		fi
		systemctl disable k8s-join
		systemctl stop k8s-join
		;;
	*)
		log "Neither k8s master nor k8s node: $ROLE"
		;;
	esac
	log "Finished k8s init for role $ROLE"
fi

# unmount the config drive if it is mounted
log "unmounting $MCONF if present"
test $MCONF && mount|grep $MCONF && umount $MCONF

touch "$INIT_COMPLETE_FLAG"
log "Finished mobiledgex init"
