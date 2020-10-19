bash 'run_cmd' do
  cwd '/tmp'
  code <<-EOH
    #{node['runCmd']}
  EOH
  only_if { node.attribute?('runCmd') }
  notifies :run, 'ruby_block[unset_cmd]', :delayed
end

ruby_block 'unset_cmd' do
  block do
    node.normal.delete('runCmd')
  end
  action :run
end
