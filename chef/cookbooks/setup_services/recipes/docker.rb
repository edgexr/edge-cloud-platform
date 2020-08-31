edgeCloudVersion = node['edgeCloudVersion']
if node.attribute?("edgeCloudVersionOverride")
  unless node['edgeCloudVersionOverride'].empty?
    Chef::Log.info("Override edgeCloudVersion from #{node['edgeCloudVersion']} to #{node['edgeCloudVersionOverride']}")
    edgeCloudVersion = node['edgeCloudVersionOverride']
  end
end

Chef::Log.info("Using edgeCloudVersion: #{edgeCloudVersion}")

docker_registry "#{node['edgeCloudImage']}" do
  regsecrets = data_bag_item('mexsecrets', 'docker_registry')
  Chef::Log.info("Login to registry: #{node['edgeCloudImage']} as user #{regsecrets['mex_docker_username']}")
  username "#{regsecrets['mex_docker_username']}"
  password "#{regsecrets['mex_docker_password']}"
end

docker_image "#{node['edgeCloudImage']}" do
  Chef::Log.info("Pull edge cloud image #{node['edgeCloudImage']}:#{edgeCloudVersion}")
  action :pull
  tag "#{edgeCloudVersion}"
end

docker_image "#{node['prometheusImage']}" do
  Chef::Log.info("Pull prometheus image #{node['prometheusImage']}:#{node['prometheusVersion']}")
  action :pull
  tag "#{node['prometheusVersion']}"
end

cmd = crmserver_cmd
docker_container "crmserver" do
  Chef::Log.info("Start crmserver container, cmd: #{cmd}")
  repo "#{node['edgeCloudImage']}"
  tag "#{edgeCloudVersion}"
  action :run
  network_mode 'host'
  restart_policy 'unless-stopped'
  env node['crmserver']['env']
  volumes ['/tmp:/tmp']
  command cmd
end

cmd = shepherd_cmd
docker_container "shepherd" do
  Chef::Log.info("Start shepherd container, cmd: #{cmd}")
  repo "#{node['edgeCloudImage']}"
  tag "#{edgeCloudVersion}"
  action :run
  network_mode 'host'
  restart_policy 'unless-stopped'
  env node['shepherd']['env']
  volumes ['/tmp:/tmp']
  command cmd
end

cookbook_file '/tmp/prometheus.yml' do
  source 'prometheus.yml'
  mode '0644'
  action :create
  force_unlink true
end

cmd = cloudlet_prometheus_cmd
docker_container "cloudletPrometheus" do
  Chef::Log.info("Start cloudlet prometheus container, cmd: #{cmd}")
  repo "#{node['prometheusImage']}"
  tag "#{node['prometheusVersion']}"
  action :run
  network_mode 'host'
  restart_policy 'unless-stopped'
  if node['cloudletPrometheus'].key?("env")
    env node['cloudletPrometheus']['env']
  end
  if node['cloudletPrometheus'].key?("publish")
    port node['cloudletPrometheus']['publish']
  end
  if node['cloudletPrometheus'].key?("label")
    labels node['cloudletPrometheus']['label']
  end
  if node['cloudletPrometheus'].key?("volume")
    volumes node['cloudletPrometheus']['volume']
  end
  user "nobody"
  working_dir "/prometheus"
  command cmd
end
