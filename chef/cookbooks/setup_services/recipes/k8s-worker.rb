
template '/home/ubuntu/prometheus-vols/cfg/prometheus.yml' do
  source 'prometheus.erb'
  variables(
    remote_write_addr: get_thanos_remote_write_addr()
  )
  owner 'ubuntu'
  group 'ubuntu'
  mode '0644'
  action :create_if_missing
end
