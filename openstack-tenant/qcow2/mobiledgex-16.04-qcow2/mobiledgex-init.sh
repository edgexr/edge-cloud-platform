#!/bin/bash
# this is run at system init time
# TODO: mark so that it does not run again 
# TODO: check for updates from edgeproxy before running

echo starting mobiledgex init >> /tmp/mobiledgex.log
date >> /tmp/mobiledgex.log
MCONF=/mnt/mobiledgex-config
mkdir $MCONF
mount `blkid -t LABEL="config-2" -odevice` $MCONF
skipinit=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.skipinit | sed -e 's/"//'g`
if [ "$skipinit" != "yes" ]; then
	echo not skipping >> /tmp/mobiledgex.log
	echo nameserver 8.8.8.8 > /etc/resolv.conf
	ipaddress=`cat $MCONF/openstack/latest/network_data.json |jq .networks[0].ip_address | sed -e 's/"//'g` 
	ifconfig ens3  $ipaddress up
	ifconfig ens3 netmask `cat $MCONF/openstack/latest/network_data.json |jq .networks[0].netmask | sed -e 's/"//'g` up
	edgeproxy=`cat $MCONF/openstack/latest/meta_data.json| jq .meta.edgeproxy | sed -e 's/"//'g` 
	ip route add default via $edgeproxy dev ens3
	ifconfig -a >>/tmp/mobiledgex.log
	ip route >> /tmp/mobiledgex.log
	hostname `cat $MCONF/openstack/latest/meta_data.json |jq .name | sed -e 's/"//'g`
	echo hostname `hostname` >> /tmp/mobiledgex.log
	role=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.role | sed -e 's/"//'g`
	echo role $role >> /tmp/mobiledgex.log
	grep -v 127.0.1.1 /etc/hosts > /tmp/hosts
	echo 127.0.1.1 `hostname` >> /tmp/hosts
	cp /tmp/hosts /etc/hosts
	skipk8s=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.skipk8s | sed -e 's/"//'g`
	if [ "$skipk8s" != "yes" ]; then
		echo not skipping k8s init >> /tmp/mobiledgex.log
		masteraddr=`cat $MCONF/openstack/latest/meta_data.json |jq .meta.k8smaster | sed -e 's/"//'g`
		if [ "$role" = "k8s-master" ]; then
			echo k8s-master init >> /tmp/mobiledgex.log
			/home/mobiledgex/k8s/install-k8s-base.sh >> /tmp/mobiledgex.log
			echo k8s-base installed >> /tmp/mobiledgex.log
			/home/mobiledgex/k8s/install-k8s-master.sh ens3 $masteraddr $ipaddress >> /tmp/mobiledgex.log
			echo k8s-master installed >> /tmp/mobiledgex.log
		fi
		if [ "$role" = "k8s-node" ]; then
			echo k8s-node init >> /tmp/mobiledgex.log
			/home/mobiledgex/k8s/install-k8s-base.sh >> /tmp/mobiledgex.log
			echo k8s-base installed >> /tmp/mobiledgex.log
			/home/mobiledgex/k8s/install-k8s-node.sh  ens3 $masteraddr $ipaddress >> /tmp/mobiledgex.log
			echo k8s-node installed >> /tmp/mobiledgex.log
		fi
		echo done k8s init for role $role >> /tmp/mobiledgex.log
	else
		echo skipping k8s init for role $role >> /tmp/mobiledgex.log
	fi
	echo $role > /etc/mobiledgex-role.txt
	echo done mobiledgex init >> /tmp/mobiledgex.log
else
	echo skip mobiledgex init >> /tmp/mobiledgex.log
fi
echo all done exiting >> /tmp/mobiledgex.log
date >> /tmp/mobiledgex.log
