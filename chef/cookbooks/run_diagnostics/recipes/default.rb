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
