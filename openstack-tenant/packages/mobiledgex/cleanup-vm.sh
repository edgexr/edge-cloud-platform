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

# must be run as root

[[ "$TRACE" == yes ]] && set -x

LOGDIR="/etc/mobiledgex"
LOGFILE="${LOGDIR}/mobiledgex_vm_cleanup.txt"
exec &> >(tee "$LOGFILE")

sudo mkdir -p "$LOGDIR"
sudo chmod 700 "$LOGDIR"

log() {
        echo "[$(date)] $*"
}

systemctl is-active --quiet kubelet
if [[ $? -eq 0 ]]; then
  log "Cleanup kubernetes setup"
  kubeadm reset -f

  if [[ -f $HOME/.kube/config ]]; then
    rm $HOME/.kube/config
  fi

  log "Disable kubelet service"
  systemctl stop kubelet
  systemctl disable kubelet

  log "Flush iptables"
  iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X

  log "Restart docker service"
  systemctl restart docker
fi

if [[ -d /home/ubuntu/envoy ]]; then
  log "Remove envoy directory"
  rm -r /home/ubuntu/envoy
fi

# stop k8s-join service if it is running
systemctl is-active --quiet k8s-join
if [[ $? -eq 0 ]]; then
  log "Stopping k8s-join service"
  systemctl disable k8s-join
  systemctl stop k8s-join
fi

# Cleanup docker setup
containers=$(docker ps -a -q)
images=$(docker ps --format "{{.Image}}" | uniq)
if [[ ! -z $containers ]]; then
  log "Cleanup docker containers: $containers"
  docker stop $containers
  docker rm -f $containers

  log "Cleanup docker images: $images"
  docker rmi -f $images
fi

# Cleanup Chef
if [[ -f /home/ubuntu/client.pem ]]; then
  log "Remove chef client.pem file"
  rm /home/ubuntu/client.pem
fi
if [[ -f /etc/chef/client.rb ]]; then
  log "Remove chef client.rb file"
  rm /etc/chef/client.rb
fi
log "Stop chef-client"
systemctl stop chef-client

echo "[$(date)] Done cleanup-vm.sh ($( pwd ))"
