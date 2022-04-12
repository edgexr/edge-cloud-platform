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
