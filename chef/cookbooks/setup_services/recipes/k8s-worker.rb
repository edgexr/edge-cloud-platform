
cookbook_file '/home/ubuntu/prometheus-vols/cfg/prometheus.yml' do
  source 'prometheus.yml'
  owner 'ubuntu'
  group 'ubuntu'
  mode '0644'
  action :create_if_missing
end
