#!/usr/bin/python
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


import requests
import sys
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

port = sys.argv[1] if len(sys.argv) > 1 else 8200

try:
    r = requests.get("https://localhost:{port}/v1/sys/health".format(port=port),
                     verify=False)
    status = r.json()
    print("vault_status available=True,initialized={initialized},sealed={sealed},standby={standby}".format(
        **status))
except:
    print('vault_status available=False')
