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

# Uses docker containers to setup cloudlet services

# A name that describes what the system you're building with Chef does.
name 'docker_crm'

# Where to find external cookbooks:
default_source :chef_server, "https://chef.mobiledgex.net/organizations/mobiledgex"

# run_list: chef-client will run these recipes in the order specified.
run_list 'chef_client_updater::default', 'recipe[runstatus_handler]', 'recipe[run_cmd]', 'recipe[setup_infra]', 'recipe[preflight_crm_checks]', 'recipe[run_diagnostics]', 'recipe[setup_services::docker]', 'recipe[set_security_policies]', 'recipe[setup_teleport]', 'recipe[copy_third_party_notice]'

# Specify a custom source for a single cookbook:
cookbook 'runstatus_handler', '= 1.0.0'
cookbook 'setup_infra', '= 1.0.0'
cookbook 'preflight_crm_checks', '= 1.0.0'
cookbook 'setup_services', '= 1.3.12'
cookbook 'docker', '= 7.7.0'
cookbook 'run_diagnostics', '= 1.0.0'
cookbook 'run_cmd', '= 1.0.0'
cookbook 'chef_client_updater', '= 3.11.0'
cookbook 'set_security_policies', '= 1.0.0'
cookbook 'setup_teleport', '= 1.1.0'
cookbook 'copy_third_party_notice', '= 1.0.1'

# Set chef-client version
# IMP: Version of chef client here needs to match the version in the base image.
#      See "openstack-tenant/packages/mobiledgex/dependencies"
default['chef_client_updater']['version'] = '17.6.18'

# Set edgeCloudVersion (i.e. edge-cloud docker base image version) for all the cloudlets
override['main']['edgeCloudVersion'] = '2021-08-14-5'
