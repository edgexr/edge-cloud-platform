#!/bin/bash

echo starting mobiledgex init
MCONF=/mnt/mobiledgex-config
mkdir $MCONF
mount `blkid -t LABEL="config-2" -odevice` $MCONF
echo nameserver 8.8.8.8 > /etc/resolv.conf
ifconfig ens3 `cat $MCONF/openstack/latest/network_data.json |jq .networks[0].ip_address | sed -e 's/"//'g` up
ifconfig ens3 netmask `cat $MCONF/openstack/latest/network_data.json |jq .networks[0].netmask | sed -e 's/"//'g` up
ip route add default via `cat $MCONF/openstack/latest/meta_data.json| jq .meta.edgeproxy | sed -e 's/"//'g` dev ens3
hostname `cat $MCONF/openstack/latest/meta_data.json |jq .name | sed -e 's/"//'g`
grep -v 127.0.1.1 /etc/hosts > /tmp/hosts
echo 127.0.1.1 `hostname` >> /tmp/hosts
cp /tmp/hosts /etc/hosts
echo done mobiledgex init
