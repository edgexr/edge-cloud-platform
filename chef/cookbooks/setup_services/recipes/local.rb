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

require 'json'

services = Hash['crmserver' => crmserver_cmd, 'shepherd' => shepherd_cmd]
services.each do |service, service_cmd|
  cKey = JSON.parse(node[service]['args']['cloudletKey'])
  cKeyStr = cKey['name'] + '.' + cKey['organization']

  Chef::Log.info("Starting #{service} #{cKey}")
  envvars = {}
  node[service]['env'].each do |envvar|
    keyval = envvar.split('=')
    envvars[keyval[0]] = keyval[1]
  end
  Chef::Log.info("Using envvars #{envvars}")

  cmd = service_cmd
  bash service do
    code <<-EOH
      nohup #{cmd} </dev/null >/tmp/#{cKeyStr}.#{service}.log 2>&1 &
    EOH
    environment envvars
  end
end
