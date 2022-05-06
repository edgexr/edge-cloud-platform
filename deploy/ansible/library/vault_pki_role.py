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

PARAM_DEFAULTS = {
    "max_lease_ttl": 259200, # 72h
}

vault_addr = None

def vault_pki_role_present(vault, data, check_mode=False):
    has_changed = False
    actions = []

    path = data.pop("path")
    rolename = data.pop("rolename")
    role_params = {
        "allow_localhost": True,
        "allowed_domains": data.pop("allowed_domains"),
        "allow_subdomains": True,
        "allowed_uri_sans": data.pop("allowed_uri_sans")
    }
    try:
        role = vault("{0}/roles/{1}".format(path, rolename))["data"]
    except Exception:
        role = {}

    for param in role_params:
        curr_param = role.get(param)
        if isinstance(curr_param, list) and len(curr_param) > 0:
            curr_param = curr_param[0]
        if curr_param != role_params[param]:
            # Create or update role
            vault("{0}/roles/{1}".format(path, rolename), method="POST",
                  json=role_params, success_code=204)
            has_changed = True
            actions.append("Created/updated role")
            break

    return (has_changed, {"actions": actions})

def vault_pki_role_absent(vault, data, check_mode=False):
    has_changed = False
    actions = []

    path = data.pop("path")
    rolename = data.pop("rolename")

    try:
        role = vault("{0}/roles/{1}".format(path, rolename))
        has_changed = True
    except Exception:
        pass

    if has_changed:
        vault("{0}/roles/{1}".format(path, rolename), method="DELETE",
              success_code=204)
        actions.append("Deleted role")

    return (has_changed, {"actions": actions})

def main():
    global vault_addr

    fields = {
        "path": {"required": True, "type": "str"},
        "rolename": {"required": True, "type": "str"},
        "allowed_domains": {"required": True, "type": "str"},
        "allowed_uri_sans": {"required": True, "type": "str"},
        "vault_addr": {"required": True, "type": "str"},
        "vault_token": {"required": True, "type": "str"},
        "state": {
            "default": "present",
            "choices": ["present", "absent"],
            "type": "str",
        },
    }
    choice_map = {
        "present": vault_pki_role_present,
        "absent": vault_pki_role_absent,
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    vault_addr = module.params.pop("vault_addr")
    vault = vault_request(vault_addr, module.params.pop("vault_token"))
    has_changed, result = choice_map.get(module.params.pop("state"))(
        vault, data=module.params, check_mode=module.check_mode)
    module.exit_json(changed=has_changed, meta=result)

if __name__ == '__main__':
    main()
