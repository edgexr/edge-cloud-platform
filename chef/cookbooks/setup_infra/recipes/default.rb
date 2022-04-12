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

# Add route if required to make sure API endpoint is reachable
# This is mostly required for GDDT environments
if node.key?("infraApiGw")
  route 'Add API Endpoint Route' do
    gateway "#{node['infraApiGw']}"
    target "#{node['infraApiAddr']}/32"
  end
end
