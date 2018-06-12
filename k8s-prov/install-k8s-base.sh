#!/bin/sh
# must run as root
# on both master and nodes
swapoff -a
apt-get update && apt-get install -y apt-transport-https curl unzip
apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
apt-get update && apt-get install -y docker-ce
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
deb http://apt.kubernetes.io/ kubernetes-xenial main
EOF
apt-get update && apt-get install -y kubelet kubeadm kubectl
sed -i "s/cgroup-driver=systemd/cgroup-driver=cgroupfs/g" /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
systemctl daemon-reload
systemctl restart kubelet
wget --quiet https://dl.google.com/go/go1.10.2.linux-amd64.tar.gz
tar xf go1.10.2.linux-amd64.tar.gz 
export PATH=`pwd`/go/bin:$PATH
export GOPATH=/usr/local
go get github.com/kubernetes-incubator/cri-tools/cmd/crictl
mkdir -p /var/lib/consul
mkdir -p /usr/share/consul
mkdir -p /etc/consul/conf.d
curl -OL https://releases.hashicorp.com/consul/0.7.5/consul_0.7.5_linux_amd64.zip
unzip consul_0.7.5_linux_amd64.zip
mv consul /usr/local/bin/consul
curl -OL https://releases.hashicorp.com/consul/0.7.5/consul_0.7.5_web_ui.zip
unzip consul_0.7.5_web_ui.zip -d dist
mv dist /usr/share/consul/ui
