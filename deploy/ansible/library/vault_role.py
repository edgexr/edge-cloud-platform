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
    "policies": [],
    "token_max_ttl": 2592000, # 720h
    "token_ttl": 60,
    "token_type": "default",
}

def vault_role_present(vault, data, check_mode=False):
    has_changed = False
    create_role = False

    role = data.pop("name")
    meta = {}
    set_params = {}

    r = vault("auth/approle/role", method="LIST", success_code=[200, 404])
    if "data" in r and role in r["data"]["keys"]:
        r = vault("auth/approle/role/{0}".format(role))

        for param in PARAM_DEFAULTS:
            current = r["data"][param]
            required = data[param]
            if isinstance(current, list):
                current = sorted(current)
                required = sorted(required)
            if current != required:
                set_params[param] = required
                has_changed = True
    else:
        # Role does not exist
        has_changed = True
        create_role = True
        set_params = data

    if has_changed:
        if check_mode:
            meta["msg"] = "skipped, running in check mode"
        else:
            vault("auth/approle/role/{0}".format(role), method="POST",
                  success_code=204,
                  json=set_params)
            meta["msg"] = "role updated"
            meta["changed_params"] = set_params
    else:
        meta["msg"] = "no change"

    if not (check_mode and create_role):
        # Role exists or was created
        r = vault("auth/approle/role/{0}/role-id".format(role))
        meta["role_id"] = r["data"]["role_id"]

    return (has_changed, meta)

def vault_role_absent(vault, data=None, check_mode=False):
    has_changed = False

    role = data["name"]
    meta = {}

    r = vault("auth/approle/role", method="LIST")
    if role in r["data"]["keys"]:
        has_changed = True
        if check_mode:
            meta["msg"] = "skipped, running in check mode"
        else:
            vault("auth/approle/role/{0}".format(role), method="DELETE",
                  success_code=204)
            meta["msg"] = "role deleted"

    return (has_changed, meta)

def main():
    fields = {
        "name": {"required": True, "type": "str"},
        "policies": {"type": "list", "default": PARAM_DEFAULTS["policies"]},
        "token_max_ttl": {"type": "int", "default": PARAM_DEFAULTS["token_max_ttl"]},
        "token_ttl": {"type": "int", "default": PARAM_DEFAULTS["token_ttl"]},
        "token_type": {"type": "str", "default": PARAM_DEFAULTS["token_type"]},
        "vault_addr": {"required": True, "type": "str"},
        "vault_token": {"required": True, "type": "str"},
        "state": {
            "default": "present",
            "choices": ["present", "absent"],
            "type": "str",
        },
    }
    choice_map = {
        "present": vault_role_present,
        "absent": vault_role_absent,
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    vault = vault_request(
        module.params.pop("vault_addr"),
        module.params.pop("vault_token")
    )
    has_changed, result = choice_map.get(module.params.pop("state"))(
        vault, data=module.params, check_mode=module.check_mode)
    module.exit_json(changed=has_changed, meta=result)

if __name__ == '__main__':
    main()
