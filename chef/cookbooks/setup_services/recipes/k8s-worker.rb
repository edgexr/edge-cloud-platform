remote_write = get_thanos_remote_write_addr
template '/home/ubuntu/prometheus-vols/cfg/prometheus.yml' do
  source 'prometheus.erb'
  variables(
    remote_write_addr: remote_write
  )
  owner 'ubuntu'
  group 'ubuntu'
  mode '0644'
  action :create_if_missing
end
