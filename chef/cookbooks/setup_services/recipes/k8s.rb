execute("Wait for K8s cluster to come up") do
  Chef::Log.info("Wait for K8s cluster to come up, there should be #{node['k8sNodeCount']} number of nodes")
  action "run"
  retries 30
  retry_delay 6
  command "kubectl get nodes | grep ' Ready' | wc -l | grep -w #{node['k8sNodeCount']}"
  returns 0
end

execute("Setup docker registry secrets") do
  action "run"
  retries 2
  retry_delay 2
  regsecrets = data_bag_item('mexsecrets', 'docker_registry')
  Chef::Log.info("Create secret to access #{node['edgeCloudImage']} as user #{regsecrets['mex_docker_username']}")
  command "kubectl create secret docker-registry mexreg-secret --docker-server=#{node['edgeCloudImage']} --docker-username=#{regsecrets['mex_docker_username']} --docker-password=#{regsecrets['mex_docker_password']} --docker-email=mobiledgex.ops@mobiledgex.com"
  returns 0
  ignore_failure true
end

crm_cmd = crmserver_cmd
shp_cmd = shepherd_cmd
prom_cmd = cloudlet_prometheus_cmd
template '/tmp/k8s-deployment.yaml' do
  source 'k8s_service.erb'
  variables services: {
	  :crmserver => {:cmd => crm_cmd, :env => node['crmserver']['env']},
	  :shepherd  => {:cmd => shp_cmd, :env => node['shepherd']['env']},
	  :cloudletPrometheus => {:cmd => prom_cmd, :env => node['cloudletPrometheus']['env']}
  }
end

execute("Setup kube pods") do
  action "run"
  command "kubectl apply -f /tmp/k8s-deployment.yaml"
  returns 0
end
