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

from string import Template

vault_addr = None

resource_tmpl = Template("""
resource "$resource" {
  roles = [$roles]
}
""")

class VaultGcpRolesetError(Exception):
    pass

def run_module():
    module_args = dict(
        name=dict(type="str", required=True),
        project=dict(type="str", required=True),
        secret_type=dict(type="str",
                         choices=["service_account_key", "access_token"],
                         default="service_account_key"),
        token_scopes=dict(type="list", required=False, default=[
            "https://www.googleapis.com/auth/cloud-platform",
        ]),
        bindings=dict(type="list", required=True),
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
    r = vault("gcp/roleset/{}".format(module.params["name"]),
              success_code=[200, 404])
    if "data" not in r and len(r["errors"]) < 1:
        # Roleset does not exist; create it
        result["changed"] = True
        result["action"] = "create"
        current_bindings = {}
    else:
        # Roleset exists; check if config needs to be changed
        current_secret_type = r["data"]["secret_type"]
        current_bindings = r["data"]["bindings"]

        if module.params["secret_type"] != current_secret_type:
            raise VaultGcpRolesetError("Can't change secret type for roleset (current: {})".format(
                current_secret_type))

    bindings_diff = {
        "added": [],
        "removed": [],
        "changed": [],
    }
    params_diff = []

    need_bindings = ""
    for b in module.params["bindings"]:
        resource = b["resource"]
        roles = b["roles"]
        roles_list = '"' + '", "'.join(roles) + '"'
        need_bindings += resource_tmpl.substitute(resource=resource, roles=roles_list)

        current_roles = current_bindings.pop(resource, None)
        if not current_roles:
            bindings_diff["removed"].append(resource)
        elif sorted(current_roles) != sorted(roles):
            bindings_diff["changed"].append(resource)

        if current_bindings:
            bindings_diff["added"] = current_bindings.keys()

        result["bindings_diff"] = bindings_diff
        for bucket in bindings_diff.keys():
            if len(bindings_diff[bucket]) > 0:
                result["changed"] = True
                result["action"] = "update"
                break

    if module.check_mode:
        return module.exit_json(**result)

    if result["changed"]:
        # Create/update roleset
        data = {
            "project": module.params["project"],
            "secret_type": module.params["secret_type"],
            "bindings": need_bindings,
        }
        if data["secret_type"] == "access_token":
            data["token_scopes"] = module.params["token_scopes"]

        r = vault("gcp/roleset/{}".format(module.params["name"]),
              method="POST",
              json=data,
              success_code=204)
        result["response"] = r

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
