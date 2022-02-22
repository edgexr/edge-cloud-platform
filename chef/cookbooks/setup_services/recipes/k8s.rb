svc_vars_primary = get_services_vars('primary')
svc_vars_secondary = get_services_vars('secondary')
hostvol_vars = get_hostvols_vars
configmap_vars = get_configmap_vars

platform_k8s('prep platform cluster') do
  action :prep_cluster
  # setting up secondary role is the last step in prep, so if this exists do not run
  not_if 'kubectl get nodes --show-labels --kubeconfig=/home/ubuntu/.kube/config|grep harole=secondary'
end

template '/home/ubuntu/k8s-deployment-redis.yaml' do
  source 'k8s_service.erb'
  owner 'ubuntu'
  group 'ubuntu'
  mode '0644'
  variables(
    harole: 'master',
    deploymentName: 'redis',
    version: node['redisVersion'],
    headlessSvcs: {
       redis: {
           serviceName: node['redisServiceName'],
           ports: { redisServicePort: { protocol: 'TCP', portNum: node['redisServicePort'] } },
           appSelector: 'redis',
       },
    },
    services: {
         redis: {
           image: node['redisImage'] + ':' + node['redisVersion'],
           serviceName: node['redisServiceName'],
           port: node['redisServicePort'],
           env: [ 'ALLOW_EMPTY_PASSWORD=yes' ],
         },
    },
    hostvols: {},
    tolerations: { master_taint_tol: { key: 'node-role.kubernetes.io/master', effect: 'NoSchedule' } },
    configmaps: {}
  )
  only_if { node.attribute?(:redisServiceName) }
end

# install redis if it is enabled and not already running consistent with the template
platform_k8s('setup redis') do
  action :setup_redis
  only_if { node.attribute?(:redisServiceName) }
  not_if 'kubectl diff -f /home/ubuntu/k8s-deployment-redis.yaml --kubeconfig=/home/ubuntu/.kube/config'
end

# If redis is not specified, create the simplex manifest. If modified, trigger simplex deployment
template '/home/ubuntu/k8s-deployment.yaml' do
  source 'k8s_service.erb'
  owner 'ubuntu'
  group 'ubuntu'
  mode '0644'
  variables(
     harole: 'simplex',
     deploymentName: 'platform-simplex',
     version: node['edgeCloudVersion'],
     services: svc_vars_primary,
     hostvols: hostvol_vars,
     configmaps: configmap_vars
   )
  not_if { node.attribute?(:redisServiceName) }
end

# If redis is specified, create the primary and secondary manifests
template '/home/ubuntu/k8s-deployment-primary.yaml' do
  source 'k8s_service.erb'
  owner 'ubuntu'
  group 'ubuntu'
  mode '0644'
  variables(
     harole: 'primary',
     deploymentName: 'platform-primary',
     version: node['edgeCloudVersion'],
     services: svc_vars_primary,
     hostvols: hostvol_vars,
     configmaps: configmap_vars
   )
  only_if { node.attribute?(:redisServiceName) }
end

template '/home/ubuntu/k8s-deployment-secondary.yaml' do
  source 'k8s_service.erb'
  owner 'ubuntu'
  group 'ubuntu'
  mode '0644'
  variables(
     harole: 'secondary',
     deploymentName: 'platform-secondary',
    version: node['edgeCloudVersion'],
     services: svc_vars_secondary,
     hostvols: hostvol_vars,
     configmaps: configmap_vars
   )
  only_if { node.attribute?(:redisServiceName) }
end

# deploy the platform in simplex mode if redis is disabled and the current state is different than the template
platform_k8s('deploy simplex platform') do
  action :deploy_simplex_platform
  not_if { node.attribute?(:redisServiceName) }
  not_if 'kubectl diff -f /home/ubuntu/k8s-deployment.yaml --kubeconfig=/home/ubuntu/.kube/config'
end

# deploy the platform in H/A mode if redis is enabled and the current state of either primary or secondary is different than the template
platform_k8s('deploy HA platform') do
  action :deploy_ha_platform
  only_if { node.attribute?(:redisServiceName) }
  not_if 'kubectl diff -f /home/ubuntu/k8s-deployment-primary.yaml --kubeconfig=/home/ubuntu/.kube/config && kubectl diff -f /home/ubuntu/k8s-deployment-secondary.yaml --kubeconfig=/home/ubuntu/.kube/config'
end
