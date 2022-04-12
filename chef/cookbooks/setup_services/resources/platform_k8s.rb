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

unified_mode true
resource_name :platform_k8s
provides :platform_k8s

action :prep_cluster do
  execute("wait-k8s-cluster, looking for #{node['k8sNodeCount']} nodes") do
    action :run
    retries 30
    retry_delay 15
    command "kubectl get nodes --kubeconfig=/home/ubuntu/.kube/config| grep ' Ready' | wc -l | grep -w #{node['k8sNodeCount']}"
    returns 0
  end

  execute('patch-coredns, prevent from running on master and add pod anti-affinity') do
    action :run
    command 'kubectl patch -n kube-system deployment coredns  -p \'{"spec": {"template": {"spec": {"tolerations": [{"key": "CriticalAddonsOnly"}], "affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{"labelSelector": {"matchExpressions": [{"key": "k8s-app", "operator": "In", "values": ["kube-dns"]}]}, "topologyKey": "kubernetes.io/hostname"}]}}}}}}\' --kubeconfig=/home/ubuntu/.kube/config'
    returns 0
  end

  execute('Setup docker registry secrets') do
    action :run
    retries 2
    retry_delay 2
    regsecrets = data_bag_item('mexsecrets', 'docker_registry')
    Chef::Log.info("Create secret to access #{node['edgeCloudImage']} as user #{regsecrets['mex_docker_username']}")
    command "kubectl create secret docker-registry mexreg-secret --docker-server=#{node['edgeCloudImage']} --docker-username=#{regsecrets['mex_docker_username']} --docker-password=#{regsecrets['mex_docker_password']} --docker-email=mobiledgex.ops@mobiledgex.com --kubeconfig=/home/ubuntu/.kube/config"
    returns 0
    ignore_failure true
  end

  execute('Assign k8s node labels for master') do
    action :run
    retries 2
    retry_delay 2
    Chef::Log.info("Setting label platform-k8s-cluster-master for #{node['platform-k8s-cluster-master']} ")
    command "kubectl label nodes #{node['platform-k8s-cluster-master'].downcase} harole=master --kubeconfig=/home/ubuntu/.kube/config"
    returns 0
    ignore_failure true
  end

  execute('Assign k8s node labels for primary') do
    action :run
    retries 2
    retry_delay 2
    Chef::Log.info("Setting label platform-k8s-cluster-primary-node for #{node['platform-k8s-cluster-primary-node']} ")
    command "kubectl label nodes #{node['platform-k8s-cluster-primary-node'].downcase} harole=primary --kubeconfig=/home/ubuntu/.kube/config"
    returns 0
    ignore_failure true
  end

  execute('Assign k8s node labels for secondary') do
    action :run
    retries 2
    retry_delay 2
    Chef::Log.info("Setting label platform-k8s-cluster-secondary-node for #{node['platform-k8s-cluster-secondary-node']} ")
    command "kubectl label nodes #{node['platform-k8s-cluster-secondary-node'].downcase} harole=secondary --kubeconfig=/home/ubuntu/.kube/config"
    returns 0
    ignore_failure true
  end
end # prep-cluster

action :setup_redis do
  execute('Setup redis deployment') do
    action :run
    command 'kubectl apply -f /home/ubuntu/k8s-deployment-redis.yaml --kubeconfig=/home/ubuntu/.kube/config'
    returns 0
  end

  execute('Wait for redis deployment to come up') do
    Chef::Log.info('Wait for redis deployment to come up')
    action :run
    retries 20
    retry_delay 6
    command 'kubectl get pods -l app=redis -l version=' + node['redisVersion'] + ' --kubeconfig=/home/ubuntu/.kube/config| grep Running'
    returns 0
    only_if { node.attribute?(:redisServicePort) }
  end
end # setup-redis

action :deploy_simplex_platform do
  execute('Setup simplex deployment') do
    action :run
    command 'kubectl apply -f /home/ubuntu/k8s-deployment.yaml --kubeconfig=/home/ubuntu/.kube/config'
    returns 0
  end

  execute('Wait for simplex platform pod to come up') do
    Chef::Log.info('Wait for simplex platform pod to come up')
    action :run
    retries 30
    retry_delay 10
    command 'kubectl get pods -l app=platform-simplex -l version=' + node['edgeCloudVersion'] + ' --kubeconfig=/home/ubuntu/.kube/config| grep Running'
    returns 0
  end
end # deploy-simplex-platform

action :deploy_ha_platform do
  # verify all nodes are still up, no retries at this stage
  execute("check-k8s-cluster, looking for #{node['k8sNodeCount']} nodes") do
    action :run
    command "kubectl get nodes --kubeconfig=/home/ubuntu/.kube/config| grep ' Ready' | wc -l | grep -w #{node['k8sNodeCount']}"
    returns 0
  end

  # to affect a switchover, delete the primary deployment and re-create
  execute('delete-primary') do
    action :run
    command 'kubectl delete -f /home/ubuntu/k8s-deployment-primary.yaml --kubeconfig=/home/ubuntu/.kube/config||true'
    returns 0
  end

  execute('create-primary') do
    action :run
    command 'kubectl create -f /home/ubuntu/k8s-deployment-primary.yaml --kubeconfig=/home/ubuntu/.kube/config'
    returns 0
  end

  execute('wait-primary-running') do
    Chef::Log.info('Wait for primary platform pod to come up')
    action :run
    retries 30
    retry_delay 15
    command 'kubectl get pods -l app=platform-primary -l version=' + node['edgeCloudVersion'] + ' --kubeconfig=/home/ubuntu/.kube/config| grep Running'
    returns 0
  end

  execute('wait-primary-init-done') do
    Chef::Log.info('Wait for primary platform pod to be ready to become active')
    action :run
    retries 30
    retry_delay 15
    command 'kubectl logs deployment/platform-primary -c crmserver --kubeconfig=/home/ubuntu/.kube/config | grep "waiting for platform to become active"'
    returns 0
  end

  execute('delete-secondary') do
    action :run
    command 'kubectl delete -f /home/ubuntu/k8s-deployment-secondary.yaml --kubeconfig=/home/ubuntu/.kube/config||true'
    returns 0
  end

  execute('create-secondary') do
    action :run
    command 'kubectl create -f /home/ubuntu/k8s-deployment-secondary.yaml --kubeconfig=/home/ubuntu/.kube/config'
    returns 0
  end

  execute('wait-secondary') do
    Chef::Log.info('Wait for seconday platform pod to come up')
    action :run
    retries 30
    retry_delay 10
    command 'kubectl get pods -l app=platform-secondary -l version=' + node['edgeCloudVersion'] + ' --kubeconfig=/home/ubuntu/.kube/config| grep Running'
    returns 0
  end
end # deploy-ha-platform
