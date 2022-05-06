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

unified_mode true
resource_name :mobiledgex_pkg
provides :mobiledgex_pkg

property :version, String, name_property: true

# Upgrade the mobiledgex package
action :upgrade do

    # Remove holds
    package %w( linux-image-virtual mobiledgex ) do
        action :unlock
    end

    # Pin the package version
    apt_preference 'mobiledgex' do
        pin "version #{new_resource.version}"
        pin_priority '1001'
    end

    # Update packages
    apt_update

    # Fix package database, install updates
    execute 'install mobiledgex' do
        command 'apt --quiet --assume-yes --fix-broken --no-remove install'
    end

    # Upgrade mobiledgex package, if still necessary
    package 'mobiledgex' do
        action :upgrade
    end

end
