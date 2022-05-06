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

docker run -d \
       -p 5000:5000 \
       --restart=always \
       --name docker-registry \
       -v `pwd`/auth:/auth \
       -v /home/bob/docker-registry:/var/lib/registry \
       -e "REGISTRY_AUTH=htpasswd" \
       -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
       -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
       -v `pwd`/certs:/certs \
       -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/fullchain.cer \
       -e REGISTRY_HTTP_TLS_KEY=/certs/registry.mobiledgex.net.key \
       registry:2

#docker run -d -p 5000:5000 --restart always --name registry registry:2
