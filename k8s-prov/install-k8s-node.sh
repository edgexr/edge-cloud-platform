#!/bin/sh
# must be run as root
#  on all nodes

if [ $# -lt 3 ]; then
	echo "Insufficient arguments"
	echo "Need interface-name master-ip my-ip"
	exit 1
fi
INTF=$1
MASTERIP=$2
MYIP=$3
echo "Interface $INTF"
echo "Master IP $MASTERIP"
echo "My IP Address: $MYIP"
#nohup consul agent -data-dir=/tmp/consul -node=`hostname` -syslog -config-dir=/etc/consul/conf.d -bind=$MYIP &
#consul info
#while [ $? -ne 0 ] ; do
#	echo Waiting for local consul
#	sleep 7
#	consul info
#done
#consul join $MASTERIP
#if [ $? -ne 0 ]; then
#	echo consul join to $MASTERIP failed
#	exit 1
#fi
#consul members
#JOIN=`consul kv get join-cmd`
#while [ $? -ne 0 ]; do
#	echo waiting for join-cmd
#	sleep 7
#	JOIN=`consul kv get join-cmd`
#done
echo wait...
sleep 60
cd /tmp
wget http://$MASTERIP:8000/k8s-join-cmd
while [ $? -ne 0 ]; do
	echo waiting for join-cmd
	sleep 7
	wget http://$MASTERIP:8000/k8s-join-cmd
done
JOIN=`cat k8s-join-cmd`
echo got join cmd
cat k8s-join-cmd
echo running $JOIN --ignore-preflight-errors=all
$JOIN --ignore-preflight-errors=all
echo done running join
