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

# Base role for common recipes to be executed

# A name that describes what the system you're building with Chef does.
name 'base'

# Where to find external cookbooks:
default_source :chef_server, "https://chef.mobiledgex.net/organizations/mobiledgex" 

# run_list: chef-client will run these recipes in the order specified.
run_list 'recipe[chef_client_updater]', 'recipe[runstatus_handler]', 'recipe[copy_resource_tracker]', 'recipe[set_security_policies]', 'recipe[setup_teleport]', 'recipe[upgrade_mobiledgex_package]'

# Specify a custom source for a single cookbook:
cookbook 'chef_client_updater', '= 3.11.0'
cookbook 'runstatus_handler', '= 1.0.0'
cookbook 'copy_resource_tracker', '= 1.0.1'
cookbook 'set_security_policies', '= 1.0.0'
cookbook 'setup_teleport', '= 1.1.0'
cookbook 'upgrade_mobiledgex_package', '= 1.1.1'

default['upgrade_mobiledgex_package']['repo'] = "https://apt.mobiledgex.net/cirrus/2022-03-16"
default['mobiledgeXPackageVersion'] = '4.10.0'

# Set chef-client version
# IMP: Version of chef client here needs to match the version in the base image.
#      See "openstack-tenant/packages/mobiledgex/dependencies"
default['chef_client_updater']['version'] = '17.6.18'
