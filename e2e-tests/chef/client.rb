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

current_dir       = File.expand_path(File.dirname(__FILE__)) 
log_level         :info
log_location      STDOUT
file_cache_path   "/tmp"
cookbook_path     "#{current_dir}/../../chef/cookbooks"
client_key        "/tmp/chef_client_key.pem"
validation_key    "/tmp/validation_key.pem"
chef_server_url   "http://127.0.0.1:8889/organizations/mobiledgex"
