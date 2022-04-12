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

name 'setup_iptables_forwarding'
maintainer 'MobiledgeX Inc.'
maintainer_email 'mobiledgex.ops@mobiledgex.com'
description 'Creates iptable rules to setup routing to internet'
version '1.0.0'
chef_version '>= 14.0'
depends 'iptables'
