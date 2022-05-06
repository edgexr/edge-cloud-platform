#!/bin/bash
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

cd /var/tmp/alertmanager
# replace deleimeter in receiver name: emailClusterAlertReceiver-mexadmin-error-email -> emailClusterAlertReceiver::mexadmin::error::email
cat config.yml | sed -E 's/(- name:.+|- receiver:.+)-(.+)-(.+)-(.+)/\1::\2::\3::\4/g' > config.yml.v2
cp config.yml config.yml.old
cp config.yml.v2 config.yml
touch /var/tmp/alertmanager/receiver_dashed_name_upgraded
