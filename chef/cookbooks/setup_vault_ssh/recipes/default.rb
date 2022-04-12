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

bash 'setup vault SSH' do
  Chef::Log.info("Setting up vault SSH from https://vault-#{node.policy_group}.mobiledgex.net")
  user 'root'
  code <<-EOH
  curl https://vault-#{node.policy_group}.mobiledgex.net/v1/ssh/public_key | tee /etc/ssh/trusted-user-ca-keys.pem
  grep "ssh-rsa" /etc/ssh/trusted-user-ca-keys.pem
  [[ $? -ne 0 ]] && exit 1
  isInFile=$(cat /etc/ssh/sshd_config | grep -c "TrustedUserCAKeys")
  if [ $isInFile -eq 0 ]; then
    echo 'TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem' | tee -a /etc/ssh/sshd_config
    systemctl reload ssh
  fi
  EOH
end

