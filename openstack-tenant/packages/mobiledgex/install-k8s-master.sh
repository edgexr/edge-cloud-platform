#!/bin/sh
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

# must run as root
# on the master
set -x
if [ $# -lt 1 ]; then
	echo "Insufficient arguments"
	echo "master-ip"
	exit 1
fi
MASTERIP=$1
echo "Master IP $MASTERIP"
HOSTNAME=`hostname`
# replace 127.0.0.1 with the internal IP address in /etc/hosts. This is needed
# if there are multiple networks on the node. 
sed -i s/"127.0.0.1 $HOSTNAME"/"$MASTERIP $HOSTNAME"/g /etc/hosts 
echo "replaced localhost with $MASTERIP in /etc/hosts"


systemctl is-active --quiet kubelet
if [ $? -ne 0 ]; then
  systemctl start kubelet
  systemctl enable kubelet
fi

which kubeadm
if [ $? -ne 0 ]; then
    echo missing kubeadm
    exit 1
fi
kubeadm init --apiserver-advertise-address=$MASTERIP --control-plane-endpoint=$MASTERIP --pod-network-cidr=192.168.0.0/16 --ignore-preflight-errors=all
if [ $? -ne 0 ]; then
    echo  kubeadm exited with error
    exit 1
fi
#export KUBECONFIG=/etc/kubernetes/admin.conf
which kubectl
if [ $? -ne 0 ]; then
    echo missing kubectl
    exit 1
fi
for d in /home/ubuntu /root; do
    mkdir -p $d/.kube
    cp  /etc/kubernetes/admin.conf $d/.kube/config
done
chown -R ubuntu:ubuntu /home/ubuntu/.kube
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl version
while [ $? -ne 0 ] ; do
    echo kubectl version failed
    sleep 7
    kubectl version
done
#kubectl apply -f https://raw.githubusercontent.com/projectcalico/canal/master/k8s-install/1.7/rbac.yaml
#if [ $? -ne 0 ]; then
#    echo kubectl exited with error installing rbac
#    exit 1
#fi
#kubectl apply -f https://raw.githubusercontent.com/projectcalico/canal/master/k8s-install/1.7/canal.yaml
# use fixed version. the original will fail validation
#kubectl apply -f https://mobiledgex:sandhill@registry.mobiledgex.net:8000/mobiledgex/canal.yaml
#curl https://docs.projectcalico.org/v3.4/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml -O
#POD_CIDR="10.244.0.0/16" sed -i -e "s?192.168.0.0/16?$POD_CIDR?g" calico.yaml
#kubectl apply -f calico.yaml
#if [ $? -ne 0 ]; then
#    #    echo kubectl exited with error installing canal
#    echo kubectl exited with error installing canal
#    exit 1
#fi
# the pod network plugin has to be done for coredns to come up


echo Checking Weave CNI download URL is available
TIMEOUT=$((SECONDS+300))
nc cloud.weave.works 443 -v -z -w 5 
while [ $? -ne 0 ] ; do
    # retry until timeout
    if [ $SECONDS -gt $TIMEOUT ] ; then
        echo Timed out waiting for Weave CNI
        exit 1
    fi
    echo Waiting to check Weave URL available - now $SECONDS timeout $TIMEOUT
    sleep 5
    nc cloud.weave.works 443 -v -z -w 5
done

echo Weave URL is reachable, install CNI

kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
if [ $? -ne 0 ] ; then
    echo Failed to install Weave
    exit 1
fi

kubectl get pods --all-namespaces
kubectl get nodes | grep NotReady
while [ $? -eq 0 ] ; do
	echo Waiting for master to be Ready
	sleep 7
	kubectl get nodes | grep NotReady
done
kubectl get nodes 
if [ $? -ne 0 ]; then
    echo kubectl exited with error doing get nodes
    exit 1
fi
kubeadm token create --ttl 0 --print-join-command | tee /tmp/k8s-join-cmd.tmp
cat /tmp/k8s-join-cmd.tmp
mv /tmp/k8s-join-cmd.tmp /var/tmp/k8s-join/k8s-join-cmd
chown ubuntu:ubuntu /var/tmp/k8s-join/k8s-join-cmd

# Start k8s-join service if not started already
systemctl is-active --quiet k8s-join
if [ $? -ne 0 ]; then
  echo "start k8s-join service"
  systemctl enable k8s-join
  systemctl start k8s-join
fi
echo master ready
