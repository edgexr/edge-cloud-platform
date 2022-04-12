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

if node.name.include? "mex-docker-vm"
  remote_file '/usr/local/bin/resource-tracker' do
    source 'https://apt:AP2XYr1wBzePUAiKENupjzzB9ki@artifactory.mobiledgex.net/artifactory/downloads/resource-tracker/v1.0.0/resource-tracker'
    checksum '703f3cf91d4fd777e620f8b3100e682bed24b84b2a348c4cb208e15d5b11e0d9'
    mode '0771' # executable
    action :create
  end
end
