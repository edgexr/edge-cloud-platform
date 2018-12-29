#!/bin/sh
# must be run as root
#  on all nodes
set -x
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
echo installing k8s node, wait...
sleep 60
cd /tmp
echo waiting for join-cmd
#wget http://$MASTERIP:8000/k8s-join-cmd
scp -i /etc/mobiledgex/id_rsa_mex $MASTERIP:/tmp/k8s-join-cmd .
while [ $? -ne 0 ]; do
	sleep 7
	#wget http://$MASTERIP:8000/k8s-join-cmd
	sudo scp -i /etc/mobiledgex/id_rsa_mex ubuntu@$MASTERIP:/tmp/k8s-join-cmd .
done
echo got join cmd
JOIN=`cat /tmp/k8s-join-cmd`
cat k8s-join-cmd
echo running $JOIN --ignore-preflight-errors=all
$JOIN --ignore-preflight-errors=all
echo finished running join
