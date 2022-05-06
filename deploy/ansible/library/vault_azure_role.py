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


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vault import vault_request

import json

vault_addr = None

class VaultAzureRoleError(Exception):
    pass

def run_module():
    module_args = dict(
        name=dict(type="str", required=True),
        azure_roles=dict(type="list", required=True),
        ttl=dict(type="int", default=300),
        max_ttl=dict(type="int", default=3600),
        vault_addr=dict(type="str", required=True),
        vault_token=dict(type="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    result = dict(
        changed=False,
        action="none",
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    vault = vault_request(module.params["vault_addr"], module.params["vault_token"])
    r = vault("azure/roles/{}".format(module.params["name"]),
              success_code=[200, 404])
    if len(r.get("errors", [])) > 0:
        raise VaultAzureRoleError("Role creation error: " + "\n".join(r["errors"]))
    elif "data" not in r:
        # Role does not exist; create it
        result["changed"] = True
        result["action"] = "create"
        current_roles = []
    else:
        # Role exists; check if config needs to be changed
        current_roles = [ { "role_id": x["role_id"], "scope": x["scope"] } \
                         for x in r["data"]["azure_roles"] ]
        if module.params["azure_roles"] != current_roles \
                or module.params["ttl"] != r["data"]["ttl"] \
                or module.params["max_ttl"] != r["data"]["max_ttl"]:
            result["changed"] = True
            result["action"] = "update"

    if module.check_mode:
        return module.exit_json(**result)

    if result["changed"]:
        # Create/update role
        data = {
            "azure_roles": json.dumps(module.params["azure_roles"]),
            "ttl": module.params["ttl"],
            "max_ttl": module.params["max_ttl"],
        }

        r = vault("azure/roles/{}".format(module.params["name"]),
              method="POST",
              json=data,
              success_code=204)
        result["response"] = r

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
