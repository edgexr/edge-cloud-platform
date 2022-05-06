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


from ansible.module_utils.basic import *
from ansible.module_utils.vault import vault_request

def vault_api_call(vault, api, method="GET", data={}, raw_response=False,
        success_code=[200], check_mode=False):
    if check_mode and method != "GET":
        return (False,
                {"msg": "Skipping {0} API call in check mode".format(method)})

    has_changed = False if method in ("GET", "LIST") else True

    meta = {}
    options = {}

    kwargs = {
        "method": method,
        "success_code": success_code,
        "raw_response": raw_response,
    }
    if data:
        options = data.pop("vault_api_options", {})
        kwargs["json"] = data

    check_first = options.get("check_first")

    if check_first:
        ckwargs = {
            "method": "GET",
            "success_code": [200, 404],
        }
        r = vault(api, **ckwargs)
        meta["response"] = r

        cdata = r.get("data", {"no-data-in-response": True})
        has_changed = False
        for key in data:
            if key in cdata and cdata[key] == data[key]:
                continue
            has_changed = True
            break

    if has_changed or method in ("GET", "LIST"):
        r = vault(api, **kwargs)
        meta["response"] = r

    return (has_changed, meta)

def main():
    fields = {
        "api": {"required": True, "type": "str"},
        "method": {"type": "str", "default": "GET"},
        "data": {"type": "dict"},
        "raw_response": {"type": "bool", "default": False},
        "success_code": {"type": "list", "elements": "int", "default": [ 200 ]},
        "vault_addr": {"required": True, "type": "str"},
        "vault_token": {"required": True, "type": "str"},
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)
    vault = vault_request(module.params["vault_addr"], module.params["vault_token"])
    has_changed, result = vault_api_call(vault,
                                         api=module.params["api"],
                                         method=module.params["method"],
                                         data=module.params["data"],
                                         raw_response=module.params["raw_response"],
                                         success_code=module.params["success_code"],
                                         check_mode=module.check_mode)
    module.exit_json(changed=has_changed, meta=result)

if __name__ == '__main__':
    main()
