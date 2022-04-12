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
echo starting mobiledgex init 
date 
MCONF=/mnt/mobiledgex-config
mkdir -p $MCONF
mount `blkid -t LABEL="config-2" -odevice` $MCONF
hostname `cat $MCONF/openstack/latest/meta_data.json |jq .name | sed -e 's/"//'g`
echo hostname `hostname` | tee -a /var/log/mobiledgex.log
grep -v 127.0.1.1 /etc/hosts | tee /tmp/hosts
echo 127.0.1.1 `hostname` | tee -a /tmp/hosts
cp /tmp/hosts /etc/hosts
# TODO destory previous holepunch. Send signal to the server side
holepunch=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.holepunch | sed -e 's/"//'g`
cat /etc/mobiledgex/holepunch.json | sed -e "s/22222/$holepunch/" | tee /tmp/holepunch.json
mv /tmp/holepunch.json /etc/mobiledgex/holepunch.json
cd /etc/mobiledgex; /etc/mobiledgex/holepunch write-systemd-file
systemctl enable holepunch
systemctl start holepunch
systemctl status holepunch
usermod -aG docker ubuntu
chmod a+rw /var/run/docker.sock
update=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.update | sed -e 's/"//'g`
skipinit=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.skipinit | sed -e 's/"//'g`
if [ "$skipinit" != "yes" ]; then
    echo mobiledgex initialization | tee -a /var/log/mobiledgex.log
    ipaddress=`cat $MCONF/openstack/latest/network_data.json |jq .networks[0].ip_address | sed -e 's/"//'g` 
    nettype=`cat $MCONF/openstack/latest/network_data.json |jq .networks[0].type | sed -e 's/"//'g` 
    if [ "$nettype" = "ipv4_dhcp" ]; then
	echo using dhcp | tee -a /var/log/mobiledgex.log
	dhclient ens3
    else
	ifconfig ens3  $ipaddress up
	ifconfig ens3 netmask `cat $MCONF/openstack/latest/network_data.json |jq .networks[0].netmask | sed -e 's/"//'g` up
	edgeproxy=`cat $MCONF/openstack/latest/meta_data.json| jq .meta.edgeproxy | sed -e 's/"//'g` 
	ip route add default via $edgeproxy dev ens3
    fi
    privatenet=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.privatenet | sed -e 's/"//'g`
    privaterouter=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.privaterouter | sed -e 's/"//'g`
    if [ "$privatenet" != "" -a "$privaterouter" != "" ]; then
	echo private route entry $privatenet via $privaterouter | tee -a /var/log/mobiledgex.log
	ip route add $privatenet via $privaterouter dev ens3
    fi
    ifconfig -a  | tee -a /var/log/mobiledgex.log
    ip route | tee -a /var/log/mobiledgex.log
    role=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.role | sed -e 's/"//'g`
    if [ "$role" = "" ]; then
	echo warning role is empty string
    else 
	echo role $role | tee -a /var/log/mobiledgex.log
    fi
    dig google.com| grep 'status: NOERROR'
    if [ $? -ne 0 ]; then
	echo add 1.1.1.1 as nameserver | tee -a /var/log/mobiledgex.log
	echo nameserver 1.1.1.1 | tee /etc/resolv.conf
    fi
    echo set name server to 1.1.1.1 | tee -a /var/log/mobiledgex.log
	if [ $? -ne 0 ]; then
	    echo jq not found | tee -a /var/log/mobiledgex.log
	    exit 1
	fi
	if [ "$update" != "" ]; then
	    echo doing update via $update | tee -a /var/log/mobiledgex.log
	    curl -s -o /etc/mobiledgex/update.sh https://mobiledgex:sandhill@registry.mobiledgex.net:8000/mobiledgex/update/$update/update.sh
	    chmod a+rx /etc/mobiledgex/update.sh
	    sh -x /etc/mobiledgex/update.sh | tee -a /var/log/mobiledgex.log
	fi
	skipk8s=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.skipk8s | sed -e 's/"//'g`
	if [ "$role" = "mex-agent-node" ]; then
		echo "initializing mex agent node" | tee -a /var/log/mobiledgex.log
	else 
		if [ "$skipk8s" != "yes" ]; then
			echo skip-k8s is not set to yes so doing k8s init | tee -a /var/log/mobiledgex.log
			masteraddr=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.k8smaster | sed -e 's/"//'g`
			if [ "$role" = "k8s-master" ]; then
				echo k8s-master init | tee -a /var/log/mobiledgex.log
				sh -x /etc/mobiledgex/install-k8s-master.sh ens3 $masteraddr $ipaddress | tee -a /var/log/mobiledgex.log
				if [ $? -ne 0 ]; then
				    echo install k8s master failed with error | tee -a /var/log/mobiledgex.log
				    exit 1
				fi
				echo k8s-master installed | tee -a /var/log/mobiledgex.log
			elif [ "$role" = "k8s-node" ]; then
				echo k8s-node init | tee -a /var/log/mobiledgex.log
				sh -x /etc/mobiledgex/install-k8s-node.sh  ens3 $masteraddr $ipaddress | tee -a /var/log/mobiledgex.log
				if [ $? -ne 0 ]; then
				    echo install k8s node failed with error | tee -a /var/log/mobiledgex.log
				    exit 1
				fi
				echo k8s-node installed | tee -a /var/log/mobiledgex.log
			else
			    echo error not k8s master and not k8s node | tee -a /var/log/mobiledgex.log
			    echo "role is " $role " and not k8s" | tee -a /var/log/mobiledgex.log
			fi
			echo finished k8s init for role $role | tee -a /var/log/mobiledgex.log
		else
			echo skipping k8s init for role $role | tee -a /var/log/mobiledgex.log
		fi
	fi
	echo $role | tee /etc/mobiledgex/role.txt
	echo finished mobiledgex init | tee -a /var/log/mobiledgex.log
else
	echo skipping mobiledgex init as told | tee -a /var/log/mobiledgex.log
fi
echo all done exiting | tee -a /var/log/mobiledgex.log
date | tee -a /var/log/mobiledgex.log
