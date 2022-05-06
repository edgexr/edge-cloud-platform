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

class VaultException(Exception):
    pass

def vault_request(addr, token):
    def vault_api_call(path, method="GET", success_code=[requests.codes.ok],
                       raw_response=False, **kwargs):
        url = "{0}/v1/{1}".format(addr, path)
        if method == "LIST":
            method = "GET"
            url += "?list=true"

        data = {
            "headers": { "X-Vault-Token": token }
        }
        data.update(kwargs)
        r = requests.request(method, url, **data)
        if not isinstance(success_code, list):
            success_code = [ success_code ]
        if r.status_code not in success_code:
            raise VaultException("Got: {3} {4} {5}: {0} {1} (Expected one of: {2})".format(
                r.status_code, r.text, success_code, method, url, data))

        if r.status_code == requests.codes.no_content:
            return ''
        if raw_response:
            return r.text
        return r.json()
    return vault_api_call
