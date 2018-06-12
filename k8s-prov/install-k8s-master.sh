#!/bin/sh
# must run as root
# on the master
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
nohup consul agent -server -bootstrap-expect=1 -data-dir=/tmp/consul -node=`hostname` -bind=$MYIP -syslog -config-dir=/etc/consul/conf.d  &
kubeadm init --apiserver-advertise-address=$MYIP --pod-network-cidr=10.244.0.0/16
#export KUBECONFIG=/etc/kubernetes/admin.conf
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
kubectl apply -f https://raw.githubusercontent.com/projectcalico/canal/master/k8s-install/1.7/rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/projectcalico/canal/master/k8s-install/1.7/canal.yaml
kubectl get pods --all-namespaces
kubectl get nodes | grep NotReady
while [ $? -eq 0 ] ; do
	echo Waiting for master to be Ready
	sleep 7
	kubectl get nodes | grep NotReady
done
kubectl get nodes 
kubeadm token create --print-join-command  > /tmp/k8s-join-cmd
consul kv put join-cmd "`cat /tmp/k8s-join-cmd`"
