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

# must be run as root
#  on all nodes
set -x
if [ $# -lt 1 ]; then
	echo "Insufficient arguments"
	echo "Need master-ip"
	exit 1
fi
MASTERIP=$1
HOSTNAME=`hostname`
# replace 127.0.0.1 with the internal IP address in /etc/hosts. This is needed
# if there are multiple networks on the node. To find the IP address derive from 
# the master which we get from metadata
echo "Master IP $MASTERIP HostName $HOSTNAME"
SUBNET=`echo $MASTERIP|awk -F"." '{print $1 "." $2 "." $3}'`
echo "subnet $SUBNET"

MYIP=`ip addr show |grep $SUBNET|awk '{print $2}'|awk -F"/" '{print $1}'`
echo "My IP $MYIP"
sed -i s/"127.0.0.1 $HOSTNAME"/"$MYIP $HOSTNAME"/g /etc/hosts 
echo "replaced localhost with $MYIP in /etc/hosts"

systemctl is-active --quiet kubelet
if [ $? -ne 0 ]; then
  systemctl start kubelet
  systemctl enable kubelet
fi

echo installing k8s node, wait...
cd /tmp

curl -sf ${MASTERIP}:20800/k8s-join-cmd >k8s-join-cmd
if [ $? -ne 0 -o ! -s k8s-join-cmd ]; then
	sleep 60
	echo waiting for join-cmd
	curl -sf ${MASTERIP}:20800/k8s-join-cmd >k8s-join-cmd
	while [ $? -ne 0 -o ! -s k8s-join-cmd ]; do
		sleep 7
		curl -sf ${MASTERIP}:20800/k8s-join-cmd >k8s-join-cmd
	done
fi
echo got join cmd
JOIN=`cat /tmp/k8s-join-cmd`
cat k8s-join-cmd
echo running $JOIN --ignore-preflight-errors=all
$JOIN --ignore-preflight-errors=all
echo finished running join
