cookbook_file "#{Chef::Config[:file_cache_path]}/runstatus_handler.rb" do
  source 'runstatus_handler.rb'
  mode "0600"
  action :nothing
end.run_action(:create)

# The end.run_action(:enable) tells Chef to do the "enable" action
# immediately on encountering the resource (i.e. during 'compile').
# The action :nothing tells Chef that it does not need to do
# anything during the 'converge' phase (as its already been enabled).

chef_handler "Chef::Handler::RunStatusHandler" do
  source "#{Chef::Config[:file_cache_path]}/runstatus_handler.rb"
  action :nothing
end.run_action(:enable)
