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

docker run -d --rm -p 8000:8000 -v /home/bob/certs:/certs -v /home/bob/files-repo:/app/public --name gohttpserver codeskyblue/gohttpserver ./gohttpserver --root /app/public --auth-type http --auth-http mobiledgex:sandhill --cors --upload --delete --title mobiledgex --cert=/certs/cert.pem --key=/certs/key.pem
