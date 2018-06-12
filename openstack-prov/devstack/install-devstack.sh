#!/bin/bash
#must be run as root

sudo useradd -s /bin/bash -d /opt/stack -m stack

echo "stack ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/stack
sudo su - stack

git clone https://git.openstack.org/openstack-dev/devstack
cd devstack

cp samples/local.conf .
./stack.sh
