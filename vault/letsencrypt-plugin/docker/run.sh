#!/bin/sh
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

set -e
if [ -z "$CF_USER" -o -z "$CF_APIKEY" ]; then
	echo "ERROR: Cloudflare credentials not provided" >&2
	exit 2
fi
if [ -z "$NS1_APIKEY" ]; then
	echo "ERROR: NS1 api key not provided" >&2
	exit 2
fi
cat >/etc/cloudflare.ini <<EOT
dns_cloudflare_email = $CF_USER
dns_cloudflare_api_key = $CF_APIKEY
EOT
chmod 400 /etc/cloudflare.ini
cat >/etc/ns1.ini <<EOT
dns_nsone_api_key = $NS1_APIKEY
EOT
chmod 400 /etc/ns1.ini
exec /usr/bin/supervisord -c /etc/supervisord.conf
