cookbook_file '/tmp/diagnostics.sh' do
  source 'diagnostics.sh'
  mode '0644'
  action :create
  force_unlink true
end

bash 'run_diagnostics' do
  cwd '/tmp'
  code <<-EOH
    bash diagnostics.sh -p #{node['artifactoryPath']} -t #{node['artifactoryToken']}
  EOH
  only_if { node.attribute?(:artifactoryPath) && node.attribute?(:artifactoryToken) }
  notifies :run, 'ruby_block[unset_diagnostics]', :delayed
end

ruby_block 'unset_diagnostics' do
  block do
    node.normal.delete('artifactoryPath')
    node.normal.delete('artifactoryToken')
  end
  action :run
end
